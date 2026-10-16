package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
)

func physical(i net.Interface) bool {
	_, err := os.Stat(filepath.Join("/sys/class/net", i.Name, "device"))
	return err == nil
}

func defaultRoutes() ([]Route, error) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}
	routes := []Route{}
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWROUTE {
			continue
		}
		if len(m.Data) < syscall.SizeofRtMsg {
			return nil, fmt.Errorf("short netlink route")
		}
		family := m.Data[0]
		if m.Data[1] != 0 || m.Data[2] != 0 || m.Data[7] != syscall.RTN_UNICAST {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			return nil, err
		}
		r := Route{Table: uint32(m.Data[4])}
		var index uint32
		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.RTA_GATEWAY:
				if family == syscall.AF_INET && len(a.Value) == 4 {
					r.Gateway = netip.AddrFrom4([4]byte(a.Value))
				}
				if family == syscall.AF_INET6 && len(a.Value) == 16 {
					r.Gateway = netip.AddrFrom16([16]byte(a.Value))
				}
			case syscall.RTA_OIF:
				if len(a.Value) >= 4 {
					index = binary.NativeEndian.Uint32(a.Value)
				}
			case syscall.RTA_PRIORITY:
				if len(a.Value) >= 4 {
					r.Metric = binary.NativeEndian.Uint32(a.Value)
				}
			case syscall.RTA_TABLE:
				if len(a.Value) >= 4 {
					r.Table = binary.NativeEndian.Uint32(a.Value)
				}
			}
		}
		if r.Table != syscall.RT_TABLE_MAIN || !r.Gateway.IsValid() || r.Gateway.IsUnspecified() || index == 0 {
			continue
		}
		iface, err := net.InterfaceByIndex(int(index))
		if err != nil {
			continue
		}
		r.Interface = iface.Name
		if r.Gateway.Is6() && r.Gateway.IsLinkLocalUnicast() {
			r.Gateway = r.Gateway.WithZone(iface.Name)
		}
		routes = append(routes, r)
	}
	return routes, nil
}
