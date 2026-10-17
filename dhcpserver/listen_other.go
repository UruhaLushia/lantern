//go:build !linux && !darwin && !windows

package dhcpserver

import (
	"errors"
	"net"
	"net/netip"
)

func listen(string, netip.Addr) (net.PacketConn, error) {
	return nil, errors.New("active DHCP requires Linux or macOS")
}
