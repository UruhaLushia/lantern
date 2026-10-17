package network

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

func physical(i net.Interface) bool {
	row := windows.MibIfRow2{InterfaceIndex: uint32(i.Index)}
	return windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row) == nil && physicalWindows(row)
}

func physicalWindows(row windows.MibIfRow2) bool {
	// HardwareInterface is bit 0 of InterfaceAndOperStatusFlags. Virtual
	// Ethernet and TUN adapters can have a MAC and an Ethernet interface type.
	return row.InterfaceAndOperStatusFlags&1 != 0 &&
		(row.Type == windows.IF_TYPE_ETHERNET_CSMACD || row.Type == windows.IF_TYPE_IEEE80211)
}

func defaultRoutes() ([]Route, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil {
		return nil, fmt.Errorf("GetIpForwardTable2: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	routes := []Route{}
	for _, row := range table.Rows() {
		if row.DestinationPrefix.PrefixLength != 0 || row.Loopback != 0 || row.ValidLifetime == 0 {
			continue
		}
		iface, err := net.InterfaceByIndex(int(row.InterfaceIndex))
		if err != nil || iface.Flags&net.FlagUp == 0 {
			continue
		}
		ipif := windows.MibIpInterfaceRow{Family: row.DestinationPrefix.Prefix.Family, InterfaceLuid: row.InterfaceLuid}
		if err := windows.GetIpInterfaceEntry(&ipif); err != nil {
			return nil, fmt.Errorf("GetIpInterfaceEntry %s family %d: %w", iface.Name, ipif.Family, err)
		}
		if r, ok := windowsDefaultRoute(row, *iface, ipif.Metric); ok {
			routes = append(routes, r)
		}
	}
	return routes, nil
}

func windowsDefaultRoute(row windows.MibIpForwardRow2, iface net.Interface, interfaceMetric uint32) (Route, bool) {
	dst := windowsRouteAddress(&row.DestinationPrefix.Prefix)
	gw := windowsRouteAddress(&row.NextHop)
	if row.DestinationPrefix.PrefixLength != 0 || row.Loopback != 0 || row.ValidLifetime == 0 ||
		!dst.IsValid() || !dst.IsUnspecified() || !gw.IsValid() || dst.Is4() != gw.Is4() ||
		gw.IsUnspecified() || gw.IsMulticast() || gw.IsLoopback() || gw.Is4In6() {
		return Route{}, false
	}
	if gw.Is6() && gw.IsLinkLocalUnicast() {
		gw = gw.WithZone(iface.Name)
	}
	// Windows selects by the sum of route and interface metrics. Saturate
	// rather than wrap when representing that sum in the shared Route type.
	metric := min(uint64(row.Metric)+uint64(interfaceMetric), uint64(math.MaxUint32))
	return Route{Interface: iface.Name, Gateway: gw, Metric: uint32(metric)}, true
}

func windowsRouteAddress(a *windows.RawSockaddrInet) netip.Addr {
	switch a.Family {
	case windows.AF_INET:
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(a)).Addr)
	case windows.AF_INET6:
		return netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(a)).Addr)
	default:
		return netip.Addr{}
	}
}
