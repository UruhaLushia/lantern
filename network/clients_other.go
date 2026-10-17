//go:build !linux && !darwin && !windows

package network

import "net/netip"

type ClientRoutes struct{}

func NewClientRoutes(Interface) (*ClientRoutes, error) { return &ClientRoutes{}, nil }
func (*ClientRoutes) Sync([]netip.Addr) error          { return nil }
func (*ClientRoutes) Close() error                     { return nil }
