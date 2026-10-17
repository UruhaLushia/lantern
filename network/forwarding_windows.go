package network

import (
	"errors"
	"fmt"
)

var ErrWindowsDatapathUnverified = errors.New("Windows gateway datapath is unverified; forwarding settings do not prove TUN egress isolation")

func ForwardingReady(iface string, ipv4, ipv6 bool) error {
	s, err := InspectWindowsInterface(iface)
	if err != nil {
		return err
	}
	for _, v := range []struct {
		enabled bool
		state   WindowsIPInterface
	}{{ipv4, s.IPv4}, {ipv6, s.IPv6}} {
		if !v.enabled {
			continue
		}
		if v.state.Error != "" {
			return errors.New(v.state.Error)
		}
		if !v.state.Connected || !v.state.Forwarding {
			return fmt.Errorf("%s LUID %d %s: connected=%t forwarding=%t; %w", iface, s.LUID,
				v.state.Family, v.state.Connected, v.state.Forwarding, ErrWindowsDatapathUnverified)
		}
	}
	if ipv4 || ipv6 {
		return ErrWindowsDatapathUnverified
	}
	return nil
}
