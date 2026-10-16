//go:build !linux && !darwin

package dhcpserver

import (
	"errors"
	"net"
)

func listen(string) (net.PacketConn, error) {
	return nil, errors.New("active DHCP requires Linux or macOS")
}
