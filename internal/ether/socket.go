package ether

import (
	"net"
	"time"
)

type Socket interface {
	ReadFrom([]byte) (int, net.Addr, error)
	WriteTo([]byte, net.Addr) (int, error)
	JoinGroup(net.HardwareAddr) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Close() error
}
