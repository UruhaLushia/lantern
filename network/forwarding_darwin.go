package network

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func ForwardingReady(iface string, ipv4, ipv6 bool) error {
	if _, err := net.InterfaceByName(iface); err != nil {
		return err
	}
	settings := map[string]uint32{}
	if ipv4 {
		settings["net.inet.ip.forwarding"] = 1
		settings["net.inet.ip.redirect"] = 0
	}
	if ipv6 {
		settings["net.inet6.ip6.forwarding"] = 1
		settings["net.inet6.ip6.redirect"] = 0
	}
	for key, want := range settings {
		value, err := unix.SysctlUint32(key)
		if err != nil {
			return err
		}
		if value != want {
			return fmt.Errorf("forwarding requires %s=%d; configure it explicitly on the host", key, want)
		}
	}
	return nil
}
