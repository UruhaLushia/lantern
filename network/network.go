package network

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"
)

type Interface struct {
	Index      int            `json:"index"`
	Name       string         `json:"name"`
	MAC        string         `json:"mac,omitempty"`
	MTU        int            `json:"mtu"`
	Up         bool           `json:"up"`
	LANCapable bool           `json:"lan_capable"`
	Physical   bool           `json:"physical"`
	Addresses  []netip.Prefix `json:"addresses"`
}

type Route struct {
	Interface string     `json:"interface"`
	Gateway   netip.Addr `json:"gateway"`
	Metric    uint32     `json:"metric"`
	Table     uint32     `json:"table,omitempty"`
}

type Snapshot struct {
	ObservedAt    time.Time    `json:"observed_at"`
	Interfaces    []Interface  `json:"interfaces"`
	DefaultRoutes []Route      `json:"default_routes"`
	DNS           []netip.Addr `json:"dns"`
	Warnings      []string     `json:"warnings,omitempty"`
}

type Selection struct {
	Interface   Interface  `json:"interface"`
	GatewayIPv4 netip.Addr `json:"gateway_ipv4,omitempty"`
	GatewayIPv6 netip.Addr `json:"gateway_ipv6,omitempty"`
}

func Discover() (Snapshot, error) {
	s := Snapshot{ObservedAt: time.Now().UTC(), Interfaces: []Interface{}, DefaultRoutes: []Route{}}
	s.DNS = systemDNS()
	ifs, err := net.Interfaces()
	if err != nil {
		return s, err
	}
	for _, iface := range ifs {
		addrs, err := iface.Addrs()
		if err != nil {
			return s, fmt.Errorf("addresses of %s: %w", iface.Name, err)
		}
		i := Interface{Index: iface.Index, Name: iface.Name, MAC: iface.HardwareAddr.String(), MTU: iface.MTU,
			Up: iface.Flags&net.FlagUp != 0, Physical: physical(iface), Addresses: []netip.Prefix{}}
		i.LANCapable = i.Up && len(iface.HardwareAddr) == 6 && iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) == 0
		for _, addr := range addrs {
			p, err := netip.ParsePrefix(addr.String())
			if err != nil {
				return s, fmt.Errorf("address on %s: %w", iface.Name, err)
			}
			i.Addresses = append(i.Addresses, p)
		}
		s.Interfaces = append(s.Interfaces, i)
	}
	sort.Slice(s.Interfaces, func(i, j int) bool { return s.Interfaces[i].Index < s.Interfaces[j].Index })
	routes, err := defaultRoutes()
	if err != nil {
		s.Warnings = append(s.Warnings, "read default routes: "+err.Error())
	} else {
		s.DefaultRoutes = routes
	}
	return s, nil
}

func (s Snapshot) Select(name string, ipv4, ipv6 netip.Addr) (Selection, error) {
	var candidates []Interface
	for _, i := range s.Interfaces {
		if name == "auto" {
			if i.LANCapable && i.Physical {
				candidates = append(candidates, i)
			}
		} else if i.Name == name && i.LANCapable {
			candidates = append(candidates, i)
		}
	}
	if len(candidates) != 1 {
		return Selection{}, fmt.Errorf("found %d usable LAN interfaces for %q; set interface explicitly", len(candidates), name)
	}
	selected := Selection{Interface: candidates[0]}
	var err error
	selected.GatewayIPv4, err = s.gateway(selected.Interface, ipv4, true)
	if err != nil {
		return selected, err
	}
	selected.GatewayIPv6, err = s.gateway(selected.Interface, ipv6, false)
	return selected, err
}

func (s Snapshot) gateway(iface Interface, override netip.Addr, ipv4 bool) (netip.Addr, error) {
	if override.IsValid() {
		if override.Is4() != ipv4 || override.Is4In6() || override.IsUnspecified() || override.IsMulticast() || override.IsLoopback() {
			return netip.Addr{}, errors.New("gateway must be a unicast address of the matching family")
		}
		return validateGateway(iface, override)
	}
	var best netip.Addr
	var metric uint32
	for _, r := range s.DefaultRoutes {
		if r.Interface != iface.Name || r.Gateway.Is4() != ipv4 {
			continue
		}
		if !best.IsValid() || r.Metric < metric {
			best, metric = r.Gateway, r.Metric
		}
	}
	if !best.IsValid() {
		return netip.Addr{}, nil
	}
	for _, r := range s.DefaultRoutes {
		if r.Interface == iface.Name && r.Gateway.Is4() == ipv4 && r.Metric == metric && r.Gateway != best {
			return netip.Addr{}, errors.New("ambiguous default gateways; set gateway explicitly")
		}
	}
	return validateGateway(iface, best)
}

func validateGateway(iface Interface, a netip.Addr) (netip.Addr, error) {
	if a.Zone() != "" && a.Zone() != iface.Name {
		return netip.Addr{}, errors.New("gateway zone does not match interface")
	}
	plain := a.WithZone("")
	for _, p := range iface.Addresses {
		if p.Addr() == plain {
			return netip.Addr{}, errors.New("gateway cannot be a local interface address")
		}
	}
	if plain.Is6() && plain.IsLinkLocalUnicast() {
		return plain.WithZone(iface.Name), nil
	}
	for _, p := range iface.Addresses {
		if p.Contains(plain) {
			if plain.Is4() && p.Bits() < 31 {
				b := plain.As4()
				n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
				hostMask := ^uint32(0) >> p.Bits()
				if n&hostMask == hostMask || n&hostMask == 0 {
					return netip.Addr{}, errors.New("IPv4 gateway cannot be a subnet network or broadcast address")
				}
			}
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("gateway %s is not on-link on %s", a, iface.Name)
}
