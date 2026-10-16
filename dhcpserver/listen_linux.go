package dhcpserver

import (
	"context"
	"golang.org/x/sys/unix"
	"net"
	"syscall"
)

func listen(iface string) (net.PacketConn, error) {
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var inner error
		err := raw.Control(func(fd uintptr) { inner = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface) })
		if err != nil {
			return err
		}
		return inner
	}}
	return config.ListenPacket(context.Background(), "udp4", "0.0.0.0:67")
}
