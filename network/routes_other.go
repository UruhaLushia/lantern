//go:build !linux && !darwin && !windows

package network

import (
	"errors"
	"net"
)

func physical(net.Interface) bool { return false }
func defaultRoutes() ([]Route, error) {
	return nil, errors.New("route discovery supports Linux and macOS only")
}
