package announce

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/UruhaLushia/lantern/discovery"
	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

type Prefix struct {
	Network           netip.Prefix  `json:"network"`
	OnLink            bool          `json:"on_link"`
	Autonomous        bool          `json:"autonomous"`
	ValidLifetime     time.Duration `json:"valid_lifetime_ns"`
	PreferredLifetime time.Duration `json:"preferred_lifetime_ns"`
}

type Options struct {
	Enabled      bool          `json:"enabled"`
	MinInterval  time.Duration `json:"min_interval_ns"`
	MaxInterval  time.Duration `json:"max_interval_ns"`
	Lifetime     time.Duration `json:"lifetime_ns"`
	RDNSS        []netip.Addr  `json:"rdnss"`
	Prefixes     []Prefix      `json:"prefixes"`
	AutoPrefixes bool          `json:"auto_prefixes"`

	Targets     []netip.Addr `json:"targets"`
	UnicastOnly bool         `json:"unicast_only"`
}

func (o Options) Normalize() (Options, error) {
	if o.MinInterval == 0 {
		o.MinInterval = 20 * time.Second
	}
	if o.MaxInterval == 0 {
		o.MaxInterval = 60 * time.Second
	}
	if o.Lifetime == 0 {
		o.Lifetime = 180 * time.Second
	}
	if o.MaxInterval < 4*time.Second || o.MaxInterval > 1800*time.Second || o.MinInterval < 3*time.Second || o.MinInterval > o.MaxInterval*3/4 {
		return o, errors.New("RA intervals require 4s <= max <= 1800s and 3s <= min <= 0.75*max")
	}
	if o.Lifetime < o.MaxInterval || o.Lifetime > 9000*time.Second || o.Lifetime%time.Second != 0 {
		return o, errors.New("RA lifetime must be whole seconds between max_interval and 9000s")
	}
	for _, ip := range o.RDNSS {
		if !ip.Is6() || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
			return o, errors.New("RDNSS requires IPv6 unicast addresses without zones")
		}
	}
	seen := make(map[netip.Addr]bool, len(o.Targets))
	for _, ip := range o.Targets {
		if !ip.Is6() || !ip.IsLinkLocalUnicast() || ip.Zone() != "" || seen[ip] {
			return o, errors.New("RA targets must be unique IPv6 link-local unicast addresses without zones")
		}
		seen[ip] = true
	}
	for _, p := range o.Prefixes {
		if !p.Network.IsValid() || !p.Network.Addr().Is6() || !p.Network.Addr().IsGlobalUnicast() || p.Network.Addr().Is4In6() || p.Network != p.Network.Masked() {
			return o, errors.New("RA prefix must be a masked non-link-local IPv6 prefix")
		}
		if p.Autonomous && p.Network.Bits() != 64 {
			return o, errors.New("SLAAC autonomous prefix must be /64")
		}
		if p.ValidLifetime <= 0 || p.ValidLifetime > time.Duration(0xffffffff)*time.Second || p.PreferredLifetime < 0 || p.PreferredLifetime > p.ValidLifetime || p.ValidLifetime%time.Second != 0 || p.PreferredLifetime%time.Second != 0 {
			return o, errors.New("invalid RA prefix lifetimes")
		}
	}
	o.RDNSS = slices.Clone(o.RDNSS)
	o.Prefixes = slices.Clone(o.Prefixes)
	o.Targets = slices.Clone(o.Targets)
	return o, nil
}

type Status struct {
	Enabled         bool       `json:"enabled"`
	Advertising     bool       `json:"advertising"`
	Source          netip.Addr `json:"source,omitzero"`
	Sent            uint64     `json:"sent"`
	Withdrawals     uint64     `json:"withdrawals"`
	LastSent        time.Time  `json:"last_sent,omitzero"`
	LastError       string     `json:"last_error,omitempty"`
	SuspendedReason string     `json:"suspended_reason,omitempty"`
}

type Upstream struct {
	Router discovery.Router
	Ready  bool
	Reason string
}

type Service struct {
	opts          Options
	iface         net.Interface
	conn          ndpConn
	upstream      func() Upstream
	mu            sync.Mutex
	status        Status
	rs            chan struct{}
	cancel        context.CancelFunc
	done          chan struct{}
	closeErr      error
	targets       []netip.Addr
	targetUpdates chan []netip.Addr
}

type ndpConn interface {
	WriteTo(ndp.Message, *ipv6.ControlMessage, netip.Addr) error
	SetWriteDeadline(time.Time) error
	Close() error
}

func Start(ctx context.Context, iface net.Interface, opts Options, upstream func() Upstream) (*Service, error) {
	opts, err := opts.Normalize()
	if err != nil {
		return nil, err
	}
	c, src, err := listenNDP(&iface)
	if err != nil {
		return nil, err
	}
	if slices.Contains(opts.Targets, src.WithZone("")) {
		_ = c.Close()
		return nil, errors.New("RA target cannot be this interface's own link-local address")
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Service{opts: opts, iface: iface, conn: c, upstream: upstream, status: Status{Enabled: true, Source: src}, rs: make(chan struct{}, 1), cancel: cancel, done: make(chan struct{}), targets: slices.Clone(opts.Targets), targetUpdates: make(chan []netip.Addr, 1)}
	go s.loop(ctx)
	return s, nil
}

func (s *Service) Solicited(source netip.Addr) {
	s.mu.Lock()
	allowed := (!s.opts.UnicastOnly && len(s.targets) == 0) || slices.Contains(s.targets, source.WithZone(""))
	s.mu.Unlock()
	if !allowed {
		return
	}
	select {
	case s.rs <- struct{}{}:
	default:
	}
}

func (s *Service) SetTargets(targets []netip.Addr) {
	targets = slices.Clone(targets)
	slices.SortFunc(targets, netip.Addr.Compare)
	targets = slices.Compact(targets)
	select {
	case <-s.targetUpdates:
	default:
	}
	select {
	case s.targetUpdates <- targets:
	default:
	}
}
func (s *Service) Snapshot() Status { s.mu.Lock(); defer s.mu.Unlock(); return s.status }
func (s *Service) Close() error     { s.cancel(); <-s.done; return errors.Join(s.closeErr, s.conn.Close()) }

func (s *Service) loop(ctx context.Context) {
	defer close(s.done)
	defer func() {
		if s.Snapshot().Advertising {
			s.closeErr = s.send(true, Upstream{})
		}
		s.mu.Lock()
		s.status.Advertising = false
		s.mu.Unlock()
	}()
	timer := time.NewTimer(0)
	defer timer.Stop()
	next := time.Now()
	solicitAfter := next.Add(time.Duration(rand.Int64N(int64(time.Second))))
	var solicitations int
	var last time.Time
	var wasReady bool
	for {
		wake := minTime(next, time.Now().Add(time.Second))
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(max(time.Duration(0), time.Until(wake)))
		solicited := false
		select {
		case <-ctx.Done():
			return
		case targets := <-s.targetUpdates:
			s.mu.Lock()
			previous := slices.Clone(s.targets)
			s.mu.Unlock()
			if slices.Equal(previous, targets) {
				continue
			}
			removed := slices.DeleteFunc(previous, func(ip netip.Addr) bool { return slices.Contains(targets, ip) })
			if len(removed) > 0 {
				_ = s.sendTo(true, Upstream{}, removed)
			}
			s.mu.Lock()
			s.targets = targets
			s.mu.Unlock()
			wasReady = false
			next = time.Now()
			continue
		case <-s.rs:
			solicited = true
		case <-timer.C:
		}
		u := s.upstream()
		now := time.Now()
		ready := u.Ready && u.Router.Address.IsValid() && u.Router.ExpiresAt.After(now)
		if !ready {
			if s.Snapshot().Advertising {
				_ = s.send(true, u)
			}
			s.mu.Lock()
			s.status.SuspendedReason = u.Reason
			if s.status.SuspendedReason == "" {
				s.status.SuspendedReason = "waiting for a live upstream RA and working system forwarding"
			}
			s.mu.Unlock()
			wasReady = false
			if u.Router.Address.IsLinkLocalUnicast() && solicitations < 3 && !now.Before(solicitAfter) {
				_ = s.conn.SetWriteDeadline(now.Add(time.Second))
				if err := s.conn.WriteTo(&ndp.RouterSolicitation{Options: []ndp.Option{
					&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: s.iface.HardwareAddr},
				}}, nil, netip.MustParseAddr("ff02::2")); err != nil {
					s.mu.Lock()
					s.status.LastError = fmt.Sprintf("request upstream RA: %v", err)
					s.mu.Unlock()
				}
				solicitations++
				solicitAfter = now.Add(4 * time.Second)
			}
			next = now.Add(time.Second)
			continue
		}
		s.mu.Lock()
		s.status.SuspendedReason = ""
		s.mu.Unlock()
		solicitations = 0
		solicitAfter = now.Add(time.Duration(rand.Int64N(int64(time.Second))))
		if !wasReady {
			next = now
			wasReady = true
		}
		if solicited {

			response := now.Add(time.Duration(rand.Int64N(int64(500*time.Millisecond) + 1)))
			if response.Before(last.Add(3 * time.Second)) {
				response = last.Add(3 * time.Second)
			}
			next = minTime(next, response)
		}
		if next.Before(last.Add(3 * time.Second)) {
			next = last.Add(3 * time.Second)
		}
		if now.Before(next) {
			continue
		}
		if err := s.send(false, u); err != nil {
			next = now.Add(3 * time.Second)
			continue
		}
		last = now
		interval := s.opts.MinInterval + time.Duration(rand.Int64N(int64(s.opts.MaxInterval-s.opts.MinInterval)+1))
		next = now.Add(interval)
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *Service) send(withdraw bool, u Upstream) error {
	s.mu.Lock()
	targets := slices.Clone(s.targets)
	s.mu.Unlock()
	if len(targets) == 0 {
		if s.opts.UnicastOnly {
			s.mu.Lock()
			s.status.Advertising = false
			s.mu.Unlock()
			return nil
		}
		targets = []netip.Addr{netip.MustParseAddr("ff02::1")}
	}
	return s.sendTo(withdraw, u, targets)
}

func (s *Service) sendTo(withdraw bool, u Upstream, targets []netip.Addr) error {
	ra := &ndp.RouterAdvertisement{CurrentHopLimit: 64, RouterSelectionPreference: ndp.High, RouterLifetime: s.opts.Lifetime, Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: s.iface.HardwareAddr}}}
	if withdraw {
		ra.RouterLifetime = 0
	}
	if len(s.opts.RDNSS) > 0 {
		life := s.opts.Lifetime
		if withdraw {
			life = 0
		}
		ra.Options = append(ra.Options, &ndp.RecursiveDNSServer{Lifetime: life, Servers: s.opts.RDNSS})
	}
	if !withdraw {
		for _, p := range s.opts.Prefixes {
			ra.Options = append(ra.Options, &ndp.PrefixInformation{Prefix: p.Network.Addr(), PrefixLength: uint8(p.Network.Bits()), OnLink: p.OnLink, AutonomousAddressConfiguration: p.Autonomous, ValidLifetime: p.ValidLifetime, PreferredLifetime: p.PreferredLifetime})
		}
		if s.opts.AutoPrefixes {
			now := time.Now()
			for _, p := range u.Router.Prefixes {
				if !p.ValidUntil.After(now) || !p.Prefix.IsValid() {
					continue
				}
				valid := p.ValidUntil.Sub(now).Truncate(time.Second)
				preferred := max(time.Duration(0), p.PreferredUntil.Sub(now).Truncate(time.Second))
				ra.Options = append(ra.Options, &ndp.PrefixInformation{Prefix: p.Prefix.Addr(), PrefixLength: uint8(p.Prefix.Bits()), OnLink: p.OnLink, AutonomousAddressConfiguration: p.Autonomous, ValidLifetime: valid, PreferredLifetime: preferred})
			}
		}
	}
	var err error
	var sent uint64
	_ = s.conn.SetWriteDeadline(time.Now().Add(time.Second))
	for _, destination := range targets {
		if e := s.conn.WriteTo(ra, nil, destination); e != nil {
			err = errors.Join(err, fmt.Errorf("RA to %s: %w", destination, e))
		} else {
			sent++
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Sent += sent
	if sent > 0 {
		s.status.LastSent = time.Now().UTC()
		s.status.SuspendedReason = ""
		if withdraw {
			s.status.Withdrawals += sent
		} else {
			s.status.Advertising = true
		}
	}
	if err != nil {
		s.status.LastError = fmt.Sprint(err)
		return err
	}
	s.status.LastError = ""
	s.status.SuspendedReason = ""
	s.status.Advertising = !withdraw
	return nil
}
