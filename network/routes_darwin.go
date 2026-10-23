package network

import (
	"net"
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/net/route"
)

func physical(i net.Interface) bool {
	return strings.HasPrefix(i.Name, "en") && len(i.HardwareAddr) == 6
}

func defaultRoutes() ([]Route, error) {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	routes := []Route{}
	for _, msg := range msgs {
		m, ok := msg.(*route.RouteMessage)
		if !ok || len(m.Addrs) <= syscall.RTAX_NETMASK || !routeAddr(m.Addrs[syscall.RTAX_DST]).IsUnspecified() {
			continue
		}
		iface, err := net.InterfaceByIndex(m.Index)
		if err != nil {
			continue
		}
		if r, ok := darwinDefaultRoute(m, *iface); ok {
			routes = append(routes, r)
		}
	}
	return routes, nil
}

func darwinDefaultRoute(m *route.RouteMessage, iface net.Interface) (Route, bool) {
	if m.Err != nil || m.Index != iface.Index || m.Flags&syscall.RTF_UP == 0 || m.Flags&syscall.RTF_GATEWAY == 0 ||
		m.Flags&(syscall.RTF_HOST|syscall.RTF_REJECT|syscall.RTF_BLACKHOLE) != 0 || len(m.Addrs) <= syscall.RTAX_NETMASK {
		return Route{}, false
	}
	dst := routeAddr(m.Addrs[syscall.RTAX_DST])
	mask := routeAddr(m.Addrs[syscall.RTAX_NETMASK])
	gw := routeAddr(m.Addrs[syscall.RTAX_GATEWAY])
	if !dst.IsValid() || !dst.IsUnspecified() || (mask.IsValid() && (!mask.IsUnspecified() || mask.Is4() != dst.Is4())) ||
		!gw.IsValid() || gw.Is4() != dst.Is4() || gw.Is4In6() || gw.IsUnspecified() || gw.IsMulticast() || gw.IsLoopback() {
		return Route{}, false
	}
	if gw.Is6() && gw.IsLinkLocalUnicast() {
		if a := m.Addrs[syscall.RTAX_GATEWAY].(*route.Inet6Addr); a.ZoneID != 0 && a.ZoneID != iface.Index {
			return Route{}, false
		}
		gw = gw.WithZone(iface.Name)
	}
	// Preserve all valid candidates. Snapshot.Select rejects different
	// gateways at equal priority instead of guessing from RIB order.
	return Route{Interface: iface.Name, Gateway: gw}, true
}

func routeAddr(a route.Addr) netip.Addr {
	switch a := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(a.IP)
	case *route.Inet6Addr:
		return netip.AddrFrom16(a.IP)
	default:
		return netip.Addr{}
	}
}
