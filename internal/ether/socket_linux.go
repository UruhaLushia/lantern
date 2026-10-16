package ether

import (
	"net"

	"github.com/mdlayher/packet"
	"golang.org/x/sys/unix"
)

func Listen(iface *net.Interface) (Socket, error) {
	filter, err := ControlFilter()
	if err != nil {
		return nil, err
	}
	return packet.Listen(iface, packet.Raw, unix.ETH_P_ALL, &packet.Config{Filter: filter})
}
