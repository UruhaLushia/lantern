//go:build !linux

package dhcpserver

import (
	"errors"
	"net"
)

func listen(string) (net.PacketConn, error) {
	return nil, errors.New("active DHCP currently supports Linux only")
}
