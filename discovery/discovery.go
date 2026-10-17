package discovery

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/UruhaLushia/lantern/device"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

type Options struct {
	Enabled    bool          `json:"enabled"`
	MDNS       bool          `json:"mdns"`
	SSDP       bool          `json:"ssdp"`
	AddressTTL time.Duration `json:"address_ttl_ns"`
	DeviceTTL  time.Duration `json:"device_ttl_ns"`
}

type Prefix struct {
	Prefix         netip.Prefix `json:"prefix"`
	OnLink         bool         `json:"on_link"`
	Autonomous     bool         `json:"autonomous"`
	ValidUntil     time.Time    `json:"valid_until"`
	PreferredUntil time.Time    `json:"preferred_until"`
}

type Router struct {
	Address      netip.Addr   `json:"address"`
	MAC          string       `json:"mac"`
	Preference   string       `json:"preference"`
	LastSeen     time.Time    `json:"last_seen"`
	ExpiresAt    time.Time    `json:"expires_at"`
	Prefixes     []Prefix     `json:"prefixes"`
	DNS          []netip.Addr `json:"dns"`
	DNSExpiresAt time.Time    `json:"dns_expires_at,omitzero"`
}

type DHCPServer struct {
	Address      netip.Addr    `json:"address"`
	MAC          string        `json:"mac"`
	SourceIP     netip.Addr    `json:"source_ip"`
	RelayIP      netip.Addr    `json:"relay_ip,omitzero"`
	OfferedIP    netip.Addr    `json:"offered_ip,omitzero"`
	SubnetMask   netip.Addr    `json:"subnet_mask,omitzero"`
	MessageType  string        `json:"message_type"`
	TakeoverHint string        `json:"takeover_hint"`
	Routers      []netip.Addr  `json:"routers"`
	DNS          []netip.Addr  `json:"dns"`
	LastSeen     time.Time     `json:"last_seen"`
	Lease        time.Duration `json:"lease_ns"`
}

type Status struct {
	Running     bool         `json:"running"`
	Frames      uint64       `json:"frames"`
	Malformed   uint64       `json:"malformed"`
	DHCPPackets uint64       `json:"dhcp_packets"`
	RAPackets   uint64       `json:"ra_packets"`
	RSPackets   uint64       `json:"rs_packets"`
	ARPEvents   uint64       `json:"arp_events"`
	NDPEvents   uint64       `json:"ndp_events"`
	MDNSPackets uint64       `json:"mdns_packets"`
	SSDPPackets uint64       `json:"ssdp_packets"`
	Routers     []Router     `json:"routers"`
	DHCPServers []DHCPServer `json:"dhcp_servers"`
	Problems    []string     `json:"problems,omitempty"`
}

type DHCPEvent struct {
	Packet    *dhcpv4.DHCPv4
	SourceIP  netip.Addr
	SourceMAC net.HardwareAddr
	Tagged    bool
	// IP-level Windows capture has no Ethernet sender. ClientHWAddr remains a
	// DHCP claim, never a verified source MAC. Unix capture retains its check.
	LinkAddressUnavailable bool
}

type Service struct {
	iface       net.Interface
	opts        Options
	store       *device.Store
	mu          sync.Mutex
	status      Status
	onDHCP      func(DHCPEvent)
	onRS        func(netip.Addr)
	conn        frameConn
	cancel      context.CancelFunc
	done        chan struct{}
	closeNative func() error
}

type frameConn interface {
	ReadFrom([]byte) (int, net.Addr, error)
	WriteTo([]byte, net.Addr) (int, error)
	SetReadDeadline(time.Time) error
	Close() error
}

func (s *Service) SetDHCPHandler(f func(DHCPEvent)) { s.mu.Lock(); s.onDHCP = f; s.mu.Unlock() }
func (s *Service) SetRSHandler(f func(netip.Addr))  { s.mu.Lock(); s.onRS = f; s.mu.Unlock() }
func (s *Service) Snapshot() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status.Clone()
}

func (v Status) Clone() Status {
	v.Problems = slices.Clone(v.Problems)
	v.Routers = slices.Clone(v.Routers)
	v.DHCPServers = slices.Clone(v.DHCPServers)
	for i := range v.Routers {
		v.Routers[i].Prefixes = slices.Clone(v.Routers[i].Prefixes)
		v.Routers[i].DNS = slices.Clone(v.Routers[i].DNS)
	}
	for i := range v.DHCPServers {
		v.DHCPServers[i].Routers = slices.Clone(v.DHCPServers[i].Routers)
		v.DHCPServers[i].DNS = slices.Clone(v.DHCPServers[i].DNS)
	}
	return v
}

func (s *Service) Close() error {
	s.cancel()
	var err error
	if s.conn != nil {
		err = s.conn.Close()
	} else if s.closeNative != nil {
		err = s.closeNative()
	}
	<-s.done
	return err
}

func (s *Service) observe(mac net.HardwareAddr, ip netip.Addr, source string, evidence ...device.Evidence) {
	_ = s.store.Observe(device.Observation{Interface: s.iface.Name, MAC: mac, IP: ip, Source: source, Evidence: evidence, TTL: s.opts.AddressTTL})
}
