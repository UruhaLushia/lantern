package network

import (
	"math"
	"net"
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func sockaddr(ip string) windows.RawSockaddrInet {
	a := netip.MustParseAddr(ip)
	var raw windows.RawSockaddrInet
	if a.Is4() {
		v := (*windows.RawSockaddrInet4)(unsafe.Pointer(&raw))
		v.Family, v.Addr = windows.AF_INET, a.As4()
	} else {
		v := (*windows.RawSockaddrInet6)(unsafe.Pointer(&raw))
		v.Family, v.Addr = windows.AF_INET6, a.As16()
	}
	return raw
}

func defaultRow(dst, gateway string, metric uint32) windows.MibIpForwardRow2 {
	return windows.MibIpForwardRow2{DestinationPrefix: windows.IpAddressPrefix{Prefix: sockaddr(dst)},
		NextHop: sockaddr(gateway), Metric: metric, ValidLifetime: math.MaxUint32}
}

func TestWindowsDefaultRouteSelection(t *testing.T) {
	lan := net.Interface{Index: 12, Name: "LAN"}
	s := Snapshot{Interfaces: []Interface{
		{Index: 12, Name: "LAN", LANCapable: true, Physical: true,
			Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24"), netip.MustParsePrefix("fe80::10/64")}},
		{Index: 13, Name: "TUN", LANCapable: true, Physical: false},
	}}
	for _, v := range []struct {
		iface  net.Interface
		row    windows.MibIpForwardRow2
		metric uint32
	}{
		{lan, defaultRow("0.0.0.0", "192.0.2.1", 10), 20},
		{lan, defaultRow("0.0.0.0", "192.0.2.2", 5), 20},
		{lan, defaultRow("::", "fe80::1", 0), 50},
		{net.Interface{Index: 13, Name: "TUN"}, defaultRow("0.0.0.0", "198.18.0.1", 0), 0},
	} {
		r, ok := windowsDefaultRoute(v.row, v.iface, v.metric)
		if !ok {
			t.Fatal("valid default route rejected")
		}
		if r.Metric != v.row.Metric+v.metric {
			t.Fatalf("metric must include interface: %+v", r)
		}
		s.DefaultRoutes = append(s.DefaultRoutes, r)
	}
	selection, err := s.Select("auto", netip.Addr{}, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if selection.Interface.Name != "LAN" || selection.GatewayIPv4.String() != "192.0.2.2" ||
		selection.GatewayIPv6.String() != "fe80::1%LAN" {
		t.Fatalf("TUN default must not replace LAN upstream: %+v", selection)
	}
	// Equal best metrics with distinct next hops require an explicit override.
	s.DefaultRoutes = append(s.DefaultRoutes, Route{Interface: "LAN", Gateway: netip.MustParseAddr("192.0.2.3"), Metric: 25})
	if _, err := s.Select("auto", netip.Addr{}, netip.Addr{}); err == nil {
		t.Fatal("ambiguous upstreams silently accepted")
	}
}

func TestWindowsDefaultRouteFiltering(t *testing.T) {
	base := defaultRow("0.0.0.0", "192.0.2.1", 1)
	for _, v := range []struct {
		name string
		edit func(*windows.MibIpForwardRow2)
	}{
		{"split default", func(r *windows.MibIpForwardRow2) { r.DestinationPrefix.PrefixLength = 1 }},
		{"nonzero destination", func(r *windows.MibIpForwardRow2) { r.DestinationPrefix.Prefix = sockaddr("192.0.2.0") }},
		{"expired", func(r *windows.MibIpForwardRow2) { r.ValidLifetime = 0 }},
		{"loopback route", func(r *windows.MibIpForwardRow2) { r.Loopback = 1 }},
		{"on-link", func(r *windows.MibIpForwardRow2) { r.NextHop = sockaddr("0.0.0.0") }},
		{"multicast", func(r *windows.MibIpForwardRow2) { r.NextHop = sockaddr("224.0.0.1") }},
		{"wrong family", func(r *windows.MibIpForwardRow2) { r.NextHop = sockaddr("fe80::1") }},
		{"unknown family", func(r *windows.MibIpForwardRow2) { r.NextHop.Family = 999 }},
	} {
		t.Run(v.name, func(t *testing.T) {
			row := base
			v.edit(&row)
			if r, ok := windowsDefaultRoute(row, net.Interface{Name: "LAN"}, 20); ok {
				t.Fatalf("invalid default route accepted: %+v", r)
			}
		})
	}
	r, ok := windowsDefaultRoute(base, net.Interface{Name: "LAN"}, math.MaxUint32)
	if !ok || r.Metric != math.MaxUint32 {
		t.Fatalf("metric overflow: %+v", r)
	}
}

func TestWindowsPhysicalInterface(t *testing.T) {
	for _, v := range []struct {
		kind uint32
		hw   uint8
		want bool
	}{
		{windows.IF_TYPE_ETHERNET_CSMACD, 1, true},
		{windows.IF_TYPE_IEEE80211, 1, true},
		{windows.IF_TYPE_ETHERNET_CSMACD, 0, false},
		{windows.IF_TYPE_TUNNEL, 1, false},
		{windows.IF_TYPE_SOFTWARE_LOOPBACK, 0, false},
	} {
		if got := physicalWindows(windows.MibIfRow2{Type: v.kind, InterfaceAndOperStatusFlags: v.hw}); got != v.want {
			t.Fatalf("type %d flags %d: physical=%t", v.kind, v.hw, got)
		}
	}
}

// Read-only API smoke test: safe on the host and on ordinary Windows CI.
func TestWindowsDiscovery(t *testing.T) {
	s, err := Discover()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Warnings) != 0 {
		t.Fatalf("route discovery failed: %v", s.Warnings)
	}
	if len(s.Interfaces) == 0 {
		t.Fatal("no interfaces returned")
	}
	for _, iface := range s.Interfaces {
		i, err := InspectWindowsInterface(iface.Name)
		if err != nil {
			t.Fatal(err)
		}
		if i.Index != uint32(iface.Index) || i.LUID == 0 || i.GUID == "" || i.Physical != iface.Physical {
			t.Fatalf("inconsistent native identity for %s: %+v", iface.Name, i)
		}
		for _, family := range [][2]bool{{true, false}, {false, true}} {
			// Even an already enabled forwarding flag must never open gateway takeover.
			if err := ForwardingReady(iface.Name, family[0], family[1]); err == nil {
				t.Fatalf("unverified datapath accepted for %s: %v", iface.Name, family)
			}
		}
	}
	if routes, err := NewClientRoutes(Interface{}); routes != nil || err == nil {
		t.Fatalf("missing LAN identity accepted: %v, %v", routes, err)
	}
}
