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
		if !ok || m.Err != nil || m.Flags&syscall.RTF_UP == 0 || m.Flags&syscall.RTF_GATEWAY == 0 || m.Flags&(syscall.RTF_REJECT|syscall.RTF_BLACKHOLE) != 0 || len(m.Addrs) <= syscall.RTAX_NETMASK {
			continue
		}
		dst := routeAddr(m.Addrs[syscall.RTAX_DST])
		mask := routeAddr(m.Addrs[syscall.RTAX_NETMASK])
		if !dst.IsValid() || !dst.IsUnspecified() || (mask.IsValid() && !mask.IsUnspecified()) {
			continue
		}
		gw := routeAddr(m.Addrs[syscall.RTAX_GATEWAY])
		if !gw.IsValid() || gw.IsUnspecified() {
			continue
		}
		iface, err := net.InterfaceByIndex(m.Index)
		if err != nil {
			continue
		}
		if gw.Is6() && gw.IsLinkLocalUnicast() {
			gw = gw.WithZone(iface.Name)
		}
		routes = append(routes, Route{Interface: iface.Name, Gateway: gw})
	}
	return routes, nil
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
