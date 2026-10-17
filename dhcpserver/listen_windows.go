package dhcpserver

import (
	"context"
	"errors"
	"math/bits"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/windows"
)

func listen(name string, local netip.Addr) (net.PacketConn, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		p, err := netip.ParsePrefix(address.String())
		if err == nil && p.Addr() == local && local.Is4() && local.IsGlobalUnicast() {
			config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
				var inner error
				err := raw.Control(func(fd uintptr) {
					inner = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_BROADCAST, 1)
					if inner == nil {
						// IP_UNICAST_IF (31) takes the interface index in network order.
						inner = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(bits.ReverseBytes32(uint32(iface.Index))))
					}
				})
				return errors.Join(err, inner)
			}}
			return config.ListenPacket(context.Background(), "udp4", net.JoinHostPort(p.Addr().String(), "67"))
		}
	}
	return nil, errors.New("DHCP requires a LAN IPv4 address")
}
