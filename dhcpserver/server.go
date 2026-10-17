package dhcpserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/UruhaLushia/lantern/device"
	"github.com/UruhaLushia/lantern/discovery"
	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/UruhaLushia/lantern/internal/state"
	"github.com/UruhaLushia/lantern/network"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

type Options struct {
	Enabled       bool          `json:"enabled"`
	ExclusivePool bool          `json:"exclusive_pool"`
	PoolStart     netip.Addr    `json:"pool_start,omitzero"`
	PoolEnd       netip.Addr    `json:"pool_end,omitzero"`
	ServerIP      netip.Addr    `json:"server_ip,omitzero"`
	Gateway       netip.Addr    `json:"gateway,omitzero"`
	DNS           []netip.Addr  `json:"dns"`
	AllowedMACs   []string      `json:"allowed_macs"`
	GatewayMACs   []string      `json:"gateway_macs"`
	Reservations  []Reservation `json:"reservations"`
	Lease         time.Duration `json:"lease_ns"`
	LeaseFile     string        `json:"lease_file"`
	ObserveWindow time.Duration `json:"observe_window_ns"`
	// OnLease prepares or revokes forwarding before acknowledging a binding.
	// It is called under the lease lock and must not call back into Service.
	OnLease func(Lease, bool) error `json:"-"`
}

func (o Options) Normalize() (Options, error) {
	var err error
	o.Reservations, err = NormalizeReservations(o.Reservations)
	if err != nil {
		return o, err
	}
	if o.Lease == 0 {
		o.Lease = 6 * time.Hour
	}
	if o.ObserveWindow == 0 {
		o.ObserveWindow = 3 * time.Second
	}
	if !o.Enabled {
		return o, nil
	}
	if !o.ExclusivePool {
		return o, errors.New("active DHCP requires exclusive_pool")
	}
	if !o.PoolStart.Is4() || !o.PoolEnd.Is4() || o.PoolStart.Compare(o.PoolEnd) > 0 || uint64(number(o.PoolEnd))-uint64(number(o.PoolStart)) > 65535 {
		return o, errors.New("DHCP pool must contain 1..65536 ordered IPv4 addresses")
	}
	if o.Lease < time.Minute || o.Lease > 30*24*time.Hour || o.Lease%time.Second != 0 {
		return o, errors.New("DHCP lease must be whole seconds between 1m and 30d")
	}
	if o.ObserveWindow < time.Second || o.ObserveWindow > time.Minute {
		return o, errors.New("DHCP observe_window must be 1s..1m")
	}
	if o.LeaseFile == "" {
		return o, errors.New("active DHCP requires an explicit lease_file for crash recovery")
	}
	if len(o.DNS) == 0 {
		return o, errors.New("active DHCP requires explicit reachable DNS addresses")
	}
	for _, ip := range o.DNS {
		if !ip.IsValid() {
			return o, errors.New("DHCP DNS entries must be valid IPv4 addresses")
		}
	}
	o.AllowedMACs = slices.Clone(o.AllowedMACs)
	o.DNS = slices.Clone(o.DNS)
	for i, m := range o.AllowedMACs {
		mac, err := net.ParseMAC(m)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || slices.Equal(mac, make([]byte, 6)) {
			return o, errors.New("DHCP allowlist requires unicast Ethernet MACs")
		}
		o.AllowedMACs[i] = mac.String()
	}
	o.GatewayMACs, err = normalizeGatewayMACs(o.GatewayMACs, o.AllowedMACs)
	if err != nil {
		return o, err
	}
	for _, r := range o.Reservations {
		if len(o.AllowedMACs) > 0 && !slices.Contains(o.AllowedMACs, r.MAC) {
			return o, fmt.Errorf("reserved MAC %s must also be in allowed_macs", r.MAC)
		}
	}
	outside := 0
	for _, r := range o.Reservations {
		if r.IP.Compare(o.PoolStart) < 0 || r.IP.Compare(o.PoolEnd) > 0 {
			outside++
		}
	}
	if uint64(number(o.PoolEnd))-uint64(number(o.PoolStart))+1+uint64(outside) > 65536 {
		return o, errors.New("DHCP pool plus reservations outside the pool exceeds 65536 addresses")
	}
	for _, ip := range append(slices.Clone(o.DNS), o.Gateway, o.ServerIP) {
		if !ip.IsValid() {
			continue
		}
		if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip == netip.MustParseAddr("255.255.255.255") {
			return o, errors.New("DHCP server/gateway/DNS must be IPv4 unicast addresses")
		}
	}
	return o, nil
}

func number(a netip.Addr) uint32 { b := a.As4(); return binary.BigEndian.Uint32(b[:]) }

type Lease struct {
	MAC           string               `json:"mac"`
	IP            netip.Addr           `json:"ip"`
	State         string               `json:"state"`
	ExpiresAt     time.Time            `json:"expires_at"`
	TransactionID dhcpv4.TransactionID `json:"transaction_id"`
	Hostname      string               `json:"hostname,omitempty"`
	VendorClass   string               `json:"vendor_class,omitempty"`
}

type Status struct {
	Enabled        bool          `json:"enabled"`
	Running        bool          `json:"running"`
	PausedReason   string        `json:"paused_reason,omitempty"`
	ObservingUntil time.Time     `json:"observing_until,omitzero"`
	Offers         uint64        `json:"offers"`
	ACKs           uint64        `json:"acks"`
	Ignored        uint64        `json:"ignored"`
	Conflicts      uint64        `json:"conflicts"`
	LastError      string        `json:"last_error,omitempty"`
	Leases         []Lease       `json:"leases"`
	Reservations   []Reservation `json:"reservations"`
	GatewayMACs    []string      `json:"gateway_macs"`
}

type savedState struct {
	Version      int     `json:"version"`
	PausedReason string  `json:"paused_reason"`
	Leases       []Lease `json:"leases"`
}

// packetObserver permits isolated protocol tests without opening a physical
// network interface. Keep Start's existing discovery.Service API unchanged.
type packetObserver interface {
	SetDHCPHandler(func(discovery.DHCPEvent))
	Send([]byte, net.HardwareAddr) error
}

type Service struct {
	reservedByMAC map[string]netip.Addr
	reservedByIP  map[netip.Addr]string
	excluded      map[netip.Addr]bool
	opts          Options
	selected      network.Selection
	observer      packetObserver
	store         *device.Store
	ready         func() error
	mu            sync.Mutex
	status        Status
	queue         chan discovery.DHCPEvent
	cancel        context.CancelFunc
	done          chan struct{}
	socket        net.PacketConn
	transmit      func([]byte, net.HardwareAddr) error
}

func Start(ctx context.Context, selected network.Selection, opts Options, observer *discovery.Service, store *device.Store, ready func() error) (*Service, error) {
	if observer == nil {
		return nil, errors.New("active DHCP requires an observer")
	}
	return start(ctx, selected, opts, observer, store, ready, listen, sendReplyFrame)
}

func start(ctx context.Context, selected network.Selection, opts Options, observer packetObserver, store *device.Store, ready func() error, open func(string, netip.Addr) (net.PacketConn, error), send func(*Service, []byte, net.HardwareAddr) error) (*Service, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !opts.Enabled || observer == nil || store == nil || ready == nil {
		return nil, errors.New("active DHCP requires enabled options, an observer, a device store and a readiness check")
	}
	opts, err := opts.Normalize()
	if err != nil {
		return nil, err
	}
	var subnet netip.Prefix
	for _, p := range selected.Interface.Addresses {
		if p.Addr().Is4() && p.Contains(opts.PoolStart) && p.Contains(opts.PoolEnd) {
			subnet = p
			if !opts.ServerIP.IsValid() {
				opts.ServerIP = p.Addr()
			}
			break
		}
	}
	if !subnet.IsValid() {
		return nil, errors.New("DHCP pool must be on the selected LAN subnet")
	}
	if !opts.Gateway.IsValid() {
		opts.Gateway = selected.GatewayIPv4
	}
	local := false
	for _, p := range selected.Interface.Addresses {
		if p.Addr() == opts.ServerIP {
			local = true
		}
	}
	if !local || !subnet.Contains(opts.ServerIP) || !subnet.Contains(opts.Gateway) {
		return nil, errors.New("DHCP server must be local and gateway must be on-link")
	}
	mask := ^uint32(0) >> (subnet.Bits())
	networkIP := number(subnet.Masked().Addr())
	broadcast := networkIP | mask
	if number(opts.PoolStart) <= networkIP || number(opts.PoolEnd) >= broadcast {
		return nil, errors.New("DHCP pool includes a network/broadcast address")
	}
	protected := append(append(slices.Clone(opts.DNS), opts.Gateway), selected.GatewayIPv4)
	for _, p := range selected.Interface.Addresses {
		if p.Addr().Is4() {
			protected = append(protected, p.Addr())
		}
	}
	for _, r := range opts.Reservations {
		if !subnet.Contains(r.IP) || number(r.IP) == networkIP || number(r.IP) == broadcast || slices.Contains(protected, r.IP) {
			return nil, fmt.Errorf("DHCP reservation %s must be on the LAN subnet and exclude network/broadcast/local/gateway/DNS addresses", r.IP)
		}
	}
	s := &Service{opts: opts, selected: selected, observer: observer, store: store, ready: ready, queue: make(chan discovery.DHCPEvent, 128), done: make(chan struct{}), status: Status{Enabled: true, Running: true, ObservingUntil: time.Now().Add(opts.ObserveWindow), Leases: []Lease{}, Reservations: opts.Reservations}}
	s.excluded = make(map[netip.Addr]bool, len(protected))
	for _, ip := range protected {
		if ip.Is4() {
			s.excluded[ip] = true
		}
	}
	s.reservedByMAC = make(map[string]netip.Addr, len(opts.Reservations))
	s.reservedByIP = make(map[netip.Addr]string, len(opts.Reservations))
	for _, r := range opts.Reservations {
		s.reservedByMAC[r.MAC], s.reservedByIP[r.IP] = r.IP, r.MAC
	}
	var saved savedState
	if err := state.Load(opts.LeaseFile, &saved); err == nil {
		if saved.Version != 1 || len(saved.Leases) > 65536 {
			return nil, errors.New("invalid DHCP lease state")
		}
		seen := map[netip.Addr]bool{}
		seenMAC := map[string]bool{}
		saved.Leases = slices.DeleteFunc(saved.Leases, func(l Lease) bool { return !l.ExpiresAt.After(time.Now()) })
		for _, l := range saved.Leases {
			_, macErr := normalizeGatewayMACs([]string{l.MAC}, opts.AllowedMACs)
			if !l.IP.Is4() || seen[l.IP] || macErr != nil || !slices.Contains([]string{"offered", "bound", "declined", "probing"}, l.State) {
				return nil, errors.New("invalid/overlapping persisted DHCP lease")
			}
			if l.State == "offered" || l.State == "bound" {
				if !s.assignable(l.MAC, l.IP) || seenMAC[l.MAC] {
					return nil, fmt.Errorf("reservation conflicts with live lease %s / %s; release the lease or wait for expiry before changing reservations", l.MAC, l.IP)
				}
				seenMAC[l.MAC] = true
			}
			if !s.managed(l.IP) {
				return nil, fmt.Errorf("DHCP address configuration no longer covers live lease/quarantine %s / %s; restore the configuration or wait for expiry", l.MAC, l.IP)
			}
			seen[l.IP] = true
		}
		s.status.PausedReason = saved.PausedReason
		s.status.Leases = saved.Leases
		for _, lease := range saved.Leases {
			if lease.State == "bound" && lease.ExpiresAt.After(time.Now()) {
				mac, _ := net.ParseMAC(lease.MAC)
				_ = store.Observe(device.Observation{Interface: selected.Interface.Name, MAC: mac, IP: lease.IP,
					Source: "dhcp-server", TTL: time.Until(lease.ExpiresAt), Evidence: []device.Evidence{
						{Field: "hostname", Value: lease.Hostname}, {Field: "vendor_class", Value: lease.VendorClass},
					}})
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load DHCP leases: %w", err)
	}
	s.socket, err = open(selected.Interface.Name, opts.ServerIP)
	if err != nil {
		return nil, err
	}
	s.transmit = observer.Send
	if send != nil {
		s.transmit = func(frame []byte, mac net.HardwareAddr) error { return send(s, frame, mac) }
	}
	for _, lease := range s.status.Leases {
		if err := s.notifyLeaseLocked(lease); err != nil {
			return nil, errors.Join(err, s.socket.Close())
		}
	}
	ctx, s.cancel = context.WithCancel(ctx)
	observer.SetDHCPHandler(s.Handle)
	go s.loop(ctx, subnet.Bits())
	return s, nil
}

func (s *Service) Handle(event discovery.DHCPEvent) {
	if event.Packet == nil {
		return
	}
	if event.Packet.OpCode == dhcpv4.OpcodeBootReply {
		server, offered := ipAddr(event.Packet.ServerIdentifier()), ipAddr(event.Packet.YourIPAddr)
		if s.managed(offered) || server == s.opts.ServerIP {
			s.mu.Lock()
			s.status.Conflicts++
			s.status.PausedReason = fmt.Sprintf("foreign DHCP server %s (source %s, Ethernet sender %s) offers %s overlapping our pool/reservations or server identity; disable DHCP on that server or isolate its allocation range, then resume", server, event.SourceIP, event.SourceMAC, offered)
			_ = s.saveLocked()
			s.mu.Unlock()
		}
		return
	}
	select {
	case s.queue <- event:
	default:
		s.mu.Lock()
		s.status.PausedReason = "DHCP event queue overflow; inspect and resume explicitly"
		s.status.LastError = s.status.PausedReason
		_ = s.saveLocked()
		s.mu.Unlock()
	}
}
func (s *Service) Snapshot() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.status
	v.Leases = slices.Clone(v.Leases)
	v.Reservations = slices.Clone(v.Reservations)
	v.GatewayMACs = slices.Clone(s.opts.GatewayMACs)
	return v
}

func normalizeGatewayMACs(macs, allowed []string) ([]string, error) {
	out := make([]string, 0, len(macs))
	for _, value := range macs {
		mac, err := net.ParseMAC(value)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || slices.Equal(mac, make([]byte, 6)) || (len(allowed) > 0 && !slices.Contains(allowed, mac.String())) {
			return nil, fmt.Errorf("gateway MAC %q must be in allowed_macs", value)
		}
		if !slices.Contains(out, mac.String()) {
			out = append(out, mac.String())
		}
	}
	return out, nil
}

func (s *Service) SetGatewayMACs(macs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalized, err := normalizeGatewayMACs(macs, s.opts.AllowedMACs)
	if err != nil {
		return err
	}
	previous := s.opts.GatewayMACs
	s.opts.GatewayMACs = normalized
	for _, lease := range s.status.Leases {
		if err := s.notifyLeaseLocked(lease); err != nil {
			s.opts.GatewayMACs = previous
			for _, old := range s.status.Leases {
				err = errors.Join(err, s.notifyLeaseLocked(old))
			}
			return err
		}
	}
	return nil
}

func (s *Service) gatewayFor(mac net.HardwareAddr) netip.Addr {
	if slices.Contains(s.opts.GatewayMACs, mac.String()) {
		return s.opts.ServerIP
	}
	return s.opts.Gateway
}
func (s *Service) Close() error {
	s.observer.SetDHCPHandler(nil)
	s.cancel()
	err := s.socket.Close()
	<-s.done
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
func (s *Service) Resume() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.PausedReason = ""
	s.status.ObservingUntil = time.Now().Add(s.opts.ObserveWindow)
	return s.saveLocked()
}
func (s *Service) inPool(ip netip.Addr) bool {
	return ip.Is4() && ip.Compare(s.opts.PoolStart) >= 0 && ip.Compare(s.opts.PoolEnd) <= 0
}
func (s *Service) saveLocked() error {
	err := state.Save(s.opts.LeaseFile, savedState{1, s.status.PausedReason, s.status.Leases})
	if err != nil {
		s.status.LastError = err.Error()
		s.status.PausedReason = "lease persistence failed"
	}
	return err
}

func (s *Service) loop(ctx context.Context, prefix int) {
	defer close(s.done)
	defer func() { s.mu.Lock(); s.status.Running = false; s.mu.Unlock() }()

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		b := make([]byte, 2048)
		for {
			if _, _, err := s.socket.ReadFrom(b); err != nil {
				return
			}
		}
	}()
	defer func() { _ = s.socket.Close(); <-drained }()
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.queue:
			s.process(ctx, event, prefix)
		}
	}
}

func (s *Service) process(ctx context.Context, event discovery.DHCPEvent, prefix int) {
	p := event.Packet
	if p == nil || p.OpCode != dhcpv4.OpcodeBootRequest || event.Tagged || len(p.ClientHWAddr) != 6 || p.ClientHWAddr[0]&1 != 0 || slices.Equal(p.ClientHWAddr, make([]byte, 6)) || (!event.LinkAddressUnavailable && !slices.Equal(p.ClientHWAddr, event.SourceMAC)) || (!ipAddr(p.GatewayIPAddr).IsUnspecified() && ipAddr(p.GatewayIPAddr).IsValid()) || p.HopCount != 0 {
		return
	}
	mac := p.ClientHWAddr.String()
	if len(s.opts.AllowedMACs) > 0 && !slices.Contains(s.opts.AllowedMACs, mac) {
		s.mu.Lock()
		s.status.Ignored++
		s.mu.Unlock()
		return
	}
	s.mu.Lock()
	blocked := s.status.PausedReason != "" || time.Now().Before(s.status.ObservingUntil)
	s.mu.Unlock()
	if blocked {
		return
	}
	if err := s.ready(); err != nil {
		s.mu.Lock()
		s.status.LastError = err.Error()
		s.mu.Unlock()
		return
	}
	server := ipAddr(p.ServerIdentifier())
	if server.IsValid() && !server.IsUnspecified() && server != s.opts.ServerIP {
		return
	}
	requested := ipAddr(p.RequestedIPAddress())
	clientIP := ipAddr(p.ClientIPAddr)
	if clientIP.IsValid() && !clientIP.IsUnspecified() {
		requested = clientIP
	}
	switch p.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		lease, err := s.offer(ctx, mac, p.TransactionID)
		if err != nil {
			s.mu.Lock()
			s.status.LastError = err.Error()
			s.mu.Unlock()
			return
		}
		s.mu.Lock()
		for i := range s.status.Leases {
			if s.status.Leases[i].MAC == mac {
				if name := strings.TrimSpace(p.HostName()); name != "" {
					s.status.Leases[i].Hostname = name
				}
				if vendor := p.ClassIdentifier(); vendor != "" {
					s.status.Leases[i].VendorClass = vendor
				}
			}
		}
		err = s.saveLocked()
		s.mu.Unlock()
		if err != nil {
			return
		}
		s.reply(p, lease.IP, dhcpv4.MessageTypeOffer, prefix)
	case dhcpv4.MessageTypeRequest:
		if !s.assignable(mac, requested) {
			return
		}
		s.mu.Lock()
		idx := slices.IndexFunc(s.status.Leases, func(l Lease) bool {
			return l.MAC == mac && l.IP == requested && l.ExpiresAt.After(time.Now()) && (l.State == "offered" || l.State == "bound")
		})
		if idx < 0 {
			s.mu.Unlock()
			return
		}
		l := &s.status.Leases[idx]
		if l.State == "offered" && l.TransactionID != p.TransactionID {
			s.mu.Unlock()
			return
		}
		l.State = "bound"
		if name := strings.TrimSpace(p.HostName()); name != "" {
			l.Hostname = name
		}
		if vendor := p.ClassIdentifier(); vendor != "" {
			l.VendorClass = vendor
		}
		l.ExpiresAt = time.Now().Add(s.opts.Lease)
		err := s.saveLocked()
		if err == nil {
			err = s.notifyLeaseLocked(*l)
		}
		if err != nil {
			s.status.LastError = err.Error()
		}
		s.mu.Unlock()
		if err != nil {
			return
		}
		s.reply(p, requested, dhcpv4.MessageTypeAck, prefix)
	case dhcpv4.MessageTypeRelease, dhcpv4.MessageTypeDecline:
		s.mu.Lock()
		for i := range s.status.Leases {
			l := &s.status.Leases[i]
			if l.MAC == mac && l.IP == requested {
				if p.MessageType() == dhcpv4.MessageTypeDecline {
					l.State = "declined"
					l.ExpiresAt = time.Now().Add(time.Hour)
				} else {
					l.ExpiresAt = time.Now()
				}
				if err := s.notifyLeaseLocked(*l); err != nil {
					s.status.LastError = err.Error()
				}
			}
		}
		_ = s.saveLocked()
		s.mu.Unlock()
	case dhcpv4.MessageTypeInform:
		s.reply(p, netip.IPv4Unspecified(), dhcpv4.MessageTypeAck, prefix)
	}
}

func (s *Service) offer(ctx context.Context, mac string, xid dhcpv4.TransactionID) (Lease, error) {
	s.mu.Lock()
	s.status.Leases = slices.DeleteFunc(s.status.Leases, func(l Lease) bool { return !l.ExpiresAt.After(time.Now()) })
	for i, l := range s.status.Leases {
		if l.MAC == mac && (l.State == "offered" || l.State == "bound") {
			l.TransactionID = xid
			l.State = "offered"
			s.status.Leases[i] = l
			err := s.saveLocked()
			s.mu.Unlock()
			return l, err
		}
	}
	devices := s.store.Snapshot()
	chosen := s.reservedIP(mac)
	if chosen.IsValid() {
		if slices.ContainsFunc(s.status.Leases, func(l Lease) bool { return l.IP == chosen }) {
			s.mu.Unlock()
			return Lease{}, fmt.Errorf("reserved IP %s is held or quarantined; no alternate address will be assigned", chosen)
		}
		for _, owner := range device.Owners(devices, s.selected.Interface.Name, chosen) {
			if owner != mac {
				s.mu.Unlock()
				return Lease{}, fmt.Errorf("reserved IP %s is in use by %s; no alternate address will be assigned", chosen, owner)
			}
		}
	}
	if !chosen.IsValid() {
		occupied := make(map[netip.Addr]bool, len(s.status.Leases))
		for _, lease := range s.status.Leases {
			occupied[lease.IP] = true
		}
		for _, d := range devices {
			if d.Interface == s.selected.Interface.Name {
				for _, address := range d.Addresses {
					occupied[address.IP] = true
				}
			}
		}
		for ip := s.opts.PoolStart; ip.IsValid() && ip.Compare(s.opts.PoolEnd) <= 0; ip = ip.Next() {
			if s.assignable(mac, ip) && !occupied[ip] {
				chosen = ip
				break
			}
		}
	}
	if !chosen.IsValid() {
		s.mu.Unlock()
		return Lease{}, errors.New("no conflict-free address available")
	}
	l := Lease{MAC: mac, IP: chosen, State: "probing", ExpiresAt: time.Now().Add(time.Minute), TransactionID: xid}
	s.status.Leases = append(s.status.Leases, l)
	s.mu.Unlock()
	if err := s.probe(chosen); err != nil {
		return l, err
	}
	t := time.NewTimer(300 * time.Millisecond)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return l, ctx.Err()
	case <-t.C:
	}
	owners := device.Owners(s.store.Snapshot(), s.selected.Interface.Name, chosen)
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := slices.IndexFunc(s.status.Leases, func(v Lease) bool { return v.MAC == mac && v.IP == chosen })
	if idx < 0 {
		return l, errors.New("lease disappeared while probing")
	}
	for _, owner := range owners {
		if owner != mac {
			s.status.Leases[idx].State = "declined"
			s.status.Leases[idx].ExpiresAt = time.Now().Add(time.Hour)
			_ = s.saveLocked()
			return l, errors.New("ARP detected an address conflict")
		}
	}
	if s.status.PausedReason != "" {
		return l, errors.New(s.status.PausedReason)
	}
	l.State = "offered"
	s.status.Leases[idx] = l
	return l, s.saveLocked()
}

func (s *Service) probe(ip netip.Addr) error {
	mac, _ := net.ParseMAC(s.selected.Interface.MAC)
	b := make([]byte, 42)
	for i := 0; i < 6; i++ {
		b[i] = 0xff
	}
	copy(b[6:], mac)
	binary.BigEndian.PutUint16(b[12:], 0x806)
	binary.BigEndian.PutUint16(b[14:], 1)
	binary.BigEndian.PutUint16(b[16:], 0x800)
	b[18] = 6
	b[19] = 4
	binary.BigEndian.PutUint16(b[20:], 1)
	copy(b[22:], mac)
	copy(b[38:], ip.AsSlice())
	return s.observer.Send(b, net.HardwareAddr(b[:6]))
}

func ipAddr(ip net.IP) netip.Addr { a, _ := netip.AddrFromSlice(ip); return a.Unmap() }

func (s *Service) reply(request *dhcpv4.DHCPv4, yi netip.Addr, kind dhcpv4.MessageType, prefix int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.PausedReason != "" {
		return
	}
	dns := make([]net.IP, len(s.opts.DNS))
	for i, ip := range s.opts.DNS {
		dns[i] = ip.AsSlice()
	}
	mod := []dhcpv4.Modifier{dhcpv4.WithMessageType(kind), dhcpv4.WithYourIP(yi.AsSlice()), dhcpv4.WithServerIP(s.opts.ServerIP.AsSlice()), dhcpv4.WithOption(dhcpv4.OptServerIdentifier(s.opts.ServerIP.AsSlice())), dhcpv4.WithOption(dhcpv4.OptRouter(s.gatewayFor(request.ClientHWAddr).AsSlice())), dhcpv4.WithOption(dhcpv4.OptDNS(dns...)), dhcpv4.WithNetmask(net.CIDRMask(prefix, 32))}
	mod = append(mod, dhcpv4.WithClientIP(request.ClientIPAddr))
	if request.MessageType() != dhcpv4.MessageTypeInform {
		mod = append(mod, dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(s.opts.Lease)))
	}
	p, err := dhcpv4.NewReplyFromRequest(request, mod...)
	if err != nil {
		return
	}
	dst := ipAddr(request.ClientIPAddr)
	mac := request.ClientHWAddr
	if !dst.IsValid() || dst.IsUnspecified() {
		dst = yi
		if request.IsBroadcast() {
			dst = netip.MustParseAddr("255.255.255.255")
			mac = net.HardwareAddr{255, 255, 255, 255, 255, 255}
		}
	}
	localMAC, _ := net.ParseMAC(s.selected.Interface.MAC)
	frame, err := ether.IPv4UDP(localMAC, mac, s.opts.ServerIP, dst, 67, 68, p.ToBytes())
	if err == nil {
		err = s.transmit(frame, mac)
	}
	if err != nil {
		s.status.LastError = err.Error()
		return
	}
	if kind == dhcpv4.MessageTypeOffer {
		s.status.Offers++
	} else {
		s.status.ACKs++
		if yi.IsValid() && !yi.IsUnspecified() {
			_ = s.store.Observe(device.Observation{Interface: s.selected.Interface.Name, MAC: request.ClientHWAddr, IP: yi,
				Source: "dhcp-server", TTL: s.opts.Lease, Evidence: []device.Evidence{
					{Field: "hostname", Value: strings.TrimSpace(request.HostName())}, {Field: "vendor_class", Value: request.ClassIdentifier()},
				}})
		}
	}
}

func (s *Service) notifyLeaseLocked(l Lease) error {
	if s.opts.OnLease != nil {
		return s.opts.OnLease(l, slices.Contains(s.opts.GatewayMACs, l.MAC))
	}
	return nil
}
