package discovery

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/UruhaLushia/lantern/device"
	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/mdlayher/ndp"
)

func (s *Service) process(f ether.Frame) {
	if f.EtherType == 0x806 {
		s.arp(f)
		return
	}
	d, err := ether.IP(f)
	if err != nil {
		s.malformed()
		return
	}
	if d.Protocol == 58 {
		s.ndp(f, d)
		return
	}
	d, err = ether.UDP(d)
	if err != nil {
		return
	}
	if d.SourcePort == 67 || d.SourcePort == 68 || d.DestinationPort == 67 || d.DestinationPort == 68 {
		if d.Source.Is4() {
			s.dhcp(f, d)
		}
		return
	}
	if s.opts.MDNS && (d.SourcePort == 5353 || d.DestinationPort == 5353) {
		s.mdns(f, d)
	}
	if s.opts.SSDP && (d.SourcePort == 1900 || d.DestinationPort == 1900) {
		s.ssdp(f, d)
	}
}

func (s *Service) malformed() { s.mu.Lock(); s.status.Malformed++; s.mu.Unlock() }

func (s *Service) arp(f ether.Frame) {
	p := f.Payload
	if len(p) < 28 || binary.BigEndian.Uint16(p[:2]) != 1 || binary.BigEndian.Uint16(p[2:4]) != 0x800 || p[4] != 6 || p[5] != 4 {
		return
	}
	op := binary.BigEndian.Uint16(p[6:8])
	if op != 1 && op != 2 {
		return
	}
	if !slices.Equal(f.SourceMAC, p[8:14]) {
		return
	}
	ip := netip.AddrFrom4([4]byte(p[14:18]))
	s.observe(f.SourceMAC, ip, "arp")
	s.mu.Lock()
	s.status.ARPEvents++
	s.mu.Unlock()
}

func addr(ip net.IP) netip.Addr { a, _ := netip.AddrFromSlice(ip); return a.Unmap() }
func addrs(ips []net.IP) []netip.Addr {
	v := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		a := addr(ip)
		if a.IsValid() {
			v = append(v, a)
		}
	}
	return v
}

func (s *Service) dhcp(f ether.Frame, d ether.Datagram) {
	p, err := dhcpv4.FromBytes(slices.Clone(d.Payload))
	if err != nil {
		s.malformed()
		return
	}
	if len(p.ClientHWAddr) != 6 {
		return
	}
	switch p.OpCode {
	case dhcpv4.OpcodeBootRequest:
		if d.SourcePort != 68 || d.DestinationPort != 67 {
			return
		}
	case dhcpv4.OpcodeBootReply:
		if d.SourcePort != 67 || (d.DestinationPort != 68 && d.DestinationPort != 67) {
			return
		}
	default:
		return
	}
	s.mu.Lock()
	s.status.DHCPPackets++
	callback := s.onDHCP
	s.mu.Unlock()
	e := []device.Evidence{{Field: "hostname", Value: p.HostName()}, {Field: "vendor_class", Value: p.ClassIdentifier()}}
	if p.HostName() == "" {
		if fqdn := p.GetOneOption(dhcpv4.OptionFQDN); len(fqdn) > 3 {
			name := ""
			if fqdn[0]&4 != 0 {
				var labels []string
				for rest := fqdn[3:]; len(rest) > 0 && rest[0] != 0; {
					n := int(rest[0])
					if n > 63 || n+1 > len(rest) {
						labels = nil
						break
					}
					labels = append(labels, string(rest[1:n+1]))
					rest = rest[n+1:]
				}
				name = strings.Join(labels, ".")
			} else {
				name = strings.TrimRight(string(fqdn[3:]), "\x00.")
			}
			e = append(e, device.Evidence{Field: "hostname", Value: name})
		}
	}
	if requested := addr(p.RequestedIPAddress()); requested.IsValid() && !requested.IsUnspecified() {
		e = append(e, device.Evidence{Field: "requested_ipv4", Value: requested.String()})
	}
	ip := addr(p.ClientIPAddr)
	if p.OpCode == dhcpv4.OpcodeBootReply {
		entry := describeDHCPServer(p, f, d)
		s.mu.Lock()
		i := slices.IndexFunc(s.status.DHCPServers, func(v DHCPServer) bool { return sameDHCPServer(v, entry) })
		if i >= 0 {
			s.status.DHCPServers[i] = entry
		} else if len(s.status.DHCPServers) < 64 {
			s.status.DHCPServers = append(s.status.DHCPServers, entry)
		}
		s.mu.Unlock()
		if p.MessageType() == dhcpv4.MessageTypeAck {
			ip = addr(p.YourIPAddr)
		} else {
			ip = netip.Addr{}
		}
	}
	if p.MessageType() == dhcpv4.MessageTypeRelease || p.MessageType() == dhcpv4.MessageTypeDecline {
		s.store.ForgetAddress(s.iface.Name, p.ClientHWAddr, ip)
		ip = netip.Addr{}
	}
	ttl := s.opts.AddressTTL
	if p.OpCode == dhcpv4.OpcodeBootReply && p.MessageType() == dhcpv4.MessageTypeAck {
		if lease := p.IPAddressLeaseTime(0); lease > 0 {
			ttl = lease
		}
	}
	if !slices.Equal(p.ClientHWAddr, s.iface.HardwareAddr) {
		_ = s.store.Observe(device.Observation{Interface: s.iface.Name, MAC: p.ClientHWAddr, IP: ip, Source: "dhcp", Evidence: e, TTL: ttl})
	}
	if callback != nil {
		callback(DHCPEvent{Packet: p, SourceIP: d.Source, SourceMAC: slices.Clone(f.SourceMAC), Tagged: f.Tagged})
	}
}

func (s *Service) ndp(f ether.Frame, d ether.Datagram) {
	if len(d.Payload) > 0 && (d.Payload[0] < 133 || d.Payload[0] > 136) {
		return
	}
	if d.HopLimit != 255 || len(d.Payload) < 8 || d.Payload[1] != 0 || !ether.ICMPv6Valid(d) {
		s.malformed()
		return
	}
	m, err := ndp.ParseMessage(d.Payload)
	if err != nil {
		s.malformed()
		return
	}
	switch m := m.(type) {
	case *ndp.RouterAdvertisement:
		if !d.Source.IsLinkLocalUnicast() {
			return
		}
		now := time.Now().UTC()
		r := Router{Address: d.Source.WithZone(s.iface.Name), MAC: f.SourceMAC.String(), Preference: "medium", LastSeen: now, ExpiresAt: now.Add(m.RouterLifetime), Prefixes: []Prefix{}, DNS: []netip.Addr{}}
		if m.RouterSelectionPreference == ndp.High {
			r.Preference = "high"
		}
		if m.RouterSelectionPreference == ndp.Low {
			r.Preference = "low"
		}
		dnsPresent := false
		for _, o := range m.Options {
			switch o := o.(type) {
			case *ndp.PrefixInformation:
				if o.PreferredLifetime > o.ValidLifetime {
					continue
				}
				p := netip.PrefixFrom(o.Prefix, int(o.PrefixLength))
				if p.IsValid() && p.Addr().IsGlobalUnicast() && !p.Addr().Is4In6() && (!o.AutonomousAddressConfiguration || p.Bits() == 64) && len(r.Prefixes) < 64 {
					r.Prefixes = append(r.Prefixes, Prefix{Prefix: p.Masked(), OnLink: o.OnLink, Autonomous: o.AutonomousAddressConfiguration, ValidUntil: now.Add(o.ValidLifetime), PreferredUntil: now.Add(o.PreferredLifetime)})
				}
			case *ndp.RecursiveDNSServer:
				dnsPresent = true
				r.DNS = slices.Clone(o.Servers[:min(len(o.Servers), 16)])
				r.DNSExpiresAt = now.Add(o.Lifetime)
			}
		}
		s.mu.Lock()
		s.status.RAPackets++
		i := slices.IndexFunc(s.status.Routers, func(v Router) bool { return v.Address == r.Address })
		if i >= 0 {
			old := s.status.Routers[i]

			for _, p := range old.Prefixes {
				if len(r.Prefixes) < 64 && p.ValidUntil.After(now) && !slices.ContainsFunc(r.Prefixes, func(v Prefix) bool { return v.Prefix == p.Prefix }) {
					r.Prefixes = append(r.Prefixes, p)
				}
			}
			if !dnsPresent && old.DNSExpiresAt.After(now) {
				r.DNS = slices.Clone(old.DNS)
				r.DNSExpiresAt = old.DNSExpiresAt
			}
			s.status.Routers[i] = r
		} else if len(s.status.Routers) < 64 {
			s.status.Routers = append(s.status.Routers, r)
		}
		s.mu.Unlock()
		s.observe(f.SourceMAC, d.Source, "ra", device.Evidence{Field: "role", Value: "router"})
	case *ndp.RouterSolicitation:
		if !d.Source.IsUnspecified() && !d.Source.IsLinkLocalUnicast() {
			return
		}
		s.mu.Lock()
		s.status.RSPackets++
		callback := s.onRS
		s.mu.Unlock()
		if !d.Source.IsUnspecified() {
			s.observe(f.SourceMAC, d.Source, "rs")
		}
		if callback != nil {
			callback(d.Source.WithZone(s.iface.Name))
		}
	case *ndp.NeighborSolicitation:
		if !d.Source.IsUnspecified() {
			s.observe(f.SourceMAC, d.Source, "ndp")
		}
		s.mu.Lock()
		s.status.NDPEvents++
		s.mu.Unlock()
	case *ndp.NeighborAdvertisement:
		if d.Source.IsUnspecified() || m.TargetAddress.IsMulticast() {
			return
		}
		s.observe(f.SourceMAC, d.Source, "ndp")
		for _, o := range m.Options {
			if ll, ok := o.(*ndp.LinkLayerAddress); ok && ll.Direction == ndp.Target && slices.Equal(ll.Addr, f.SourceMAC) {
				s.observe(ll.Addr, m.TargetAddress, "ndp-advertisement")
			}
		}
		s.mu.Lock()
		s.status.NDPEvents++
		s.mu.Unlock()
	}
}
