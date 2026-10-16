package dhcpserver

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func listen(name string) (net.PacketConn, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var inner error
		err := raw.Control(func(fd uintptr) {
			inner = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index)
		})
		if err != nil {
			return err
		}
		return inner
	}}
	return config.ListenPacket(context.Background(), "udp4", "0.0.0.0:67")
}
