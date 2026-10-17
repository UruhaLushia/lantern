// Package wingateway forwards selected LAN clients through an existing Windows
// IPv4 route interface. It never opens or configures that interface's TUN.
package wingateway

import (
	"context"
	"errors"

	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/UruhaLushia/lantern/internal/wincapture"
	"github.com/UruhaLushia/lantern/internal/wininject"
	"github.com/UruhaLushia/lantern/network"
)

type Options struct {
	Interface, LocalIPv4, EgressInterface string
	DriverDirectory                       string
	AllowDriverLoad                       bool
	Clients                               []netip.Addr
	BatchSize                             int
}

type Status struct {
	Running     bool   `json:"running"`
	Forwarded   uint64 `json:"forwarded"`
	Dropped     uint64 `json:"dropped"`
	SelfIgnored uint64 `json:"self_ignored"`
	SendCalls   uint64 `json:"send_calls"`
	LastError   string `json:"last_error,omitempty"`
}

type Service struct {
	observerMu                                 sync.Mutex
	observer                                   atomic.Pointer[packetObserver]
	opts                                       Options
	lan, egress                                network.WindowsInterface
	rx                                         *wincapture.Socket
	tx                                         *wininject.Sender
	sources                                    atomic.Pointer[sourceSet]
	sourceMu                                   sync.Mutex
	manual                                     sourceSet
	bindings                                   map[string]binding
	lanPrefixes                                []netip.Prefix
	cancel                                     context.CancelFunc
	done                                       chan struct{}
	mu                                         sync.Mutex
	err                                        error
	forwarded, dropped, selfIgnored, sendCalls atomic.Uint64
}

type packetObserver struct{ consume func([]byte) }

// SetPacketObserver shares the existing native receiver with DHCP discovery.
// The callback must not retain the borrowed slice. Replacing it waits for any
// active callback, so discovery can detach before closing its own lifecycle.
func (s *Service) SetPacketObserver(consume func([]byte)) {
	s.observerMu.Lock()
	defer s.observerMu.Unlock()
	var observer *packetObserver
	if consume != nil {
		observer = &packetObserver{consume}
	}
	s.observer.Store(observer)
}

func (s *Service) observe(packet []byte) {
	if s.observer.Load() == nil {
		return
	}
	s.observerMu.Lock()
	defer s.observerMu.Unlock()
	if observer := s.observer.Load(); observer != nil {
		observer.consume(packet)
	}
}

func Start(ctx context.Context, opts Options) (_ *Service, err error) {
	if runtime.GOARCH != "amd64" {
		return nil, errors.New("Windows IPv4 injection currently requires amd64")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.BatchSize == 0 {
		opts.BatchSize = 1
	}
	if opts.BatchSize < 1 || opts.BatchSize > 16 {
		return nil, errors.New("batch size must be 1..16")
	}
	lan, err := network.InspectWindowsInterface(opts.Interface)
	if err != nil {
		return nil, err
	}
	egress, err := network.InspectWindowsInterface(opts.EgressInterface)
	if err != nil {
		return nil, err
	}
	if lan.IPv4.Error != "" || !lan.Physical || !lan.IPv4.Connected || lan.IPv4.Forwarding ||
		egress.Physical || lan.LUID == egress.LUID || egress.IPv4.Error != "" || !egress.IPv4.Forwarding {
		return nil, errors.New("requires a connected physical LAN with forwarding OFF and an existing forwarding-enabled egress")
	}
	local, err := netip.ParseAddr(opts.LocalIPv4)
	if err != nil || !local.Is4() {
		return nil, errors.New("specify the LAN's existing local IPv4 address")
	}
	iface, err := net.InterfaceByIndex(int(lan.Index))
	if err != nil {
		return nil, err
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	found := false
	for _, address := range addresses {
		p, parseErr := netip.ParsePrefix(address.String())
		found = found || (parseErr == nil && p.Addr() == local)
	}
	if !found {
		return nil, errors.New("local IPv4 does not belong to the selected LAN")
	}
	if err := verifyLAN(lan, local); err != nil {
		return nil, err
	}
	s := &Service{opts: opts, lan: lan, egress: egress, bindings: make(map[string]binding), done: make(chan struct{})}
	for _, address := range addresses {
		if p, err := netip.ParsePrefix(address.String()); err == nil && p.Addr().Is4() {
			s.lanPrefixes = append(s.lanPrefixes, p)
		}
	}
	if err := s.setClients(opts.Clients); err != nil {
		return nil, err
	}
	if err := verifyTUNRoute(egress, netip.MustParseAddr("1.1.1.1")); err != nil {
		return nil, err
	}
	s.rx, err = wincapture.Open(local)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if s.tx != nil {
				err = errors.Join(err, s.tx.Close())
			}
			err = errors.Join(err, s.rx.Close())
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.tx, err = wininject.Open(opts.DriverDirectory, opts.AllowDriverLoad)
	if err != nil {
		return nil, err
	}
	ctx, s.cancel = context.WithCancel(ctx)
	go s.run(ctx)
	return s, nil
}

func (s *Service) Ready() error {
	select {
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return errors.Join(net.ErrClosed, s.err)
	default:
		return nil
	}
}

func (s *Service) Snapshot() Status {
	v := Status{Running: s.Ready() == nil, Forwarded: s.forwarded.Load(), Dropped: s.dropped.Load(), SelfIgnored: s.selfIgnored.Load(), SendCalls: s.sendCalls.Load()}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		v.LastError = s.err.Error()
	}
	return v
}

func (s *Service) Close() error {
	s.cancel()
	<-s.done // Never interrupt a synchronous native send or unload the driver.
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Service) run(ctx context.Context) {
	err := s.forward(ctx)
	err = errors.Join(err, s.tx.Close())
	err = errors.Join(err, s.rx.Close())
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
	close(s.done)
}
