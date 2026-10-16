//go:build !darwin

package announce

import (
	"net"
	"net/netip"

	"github.com/mdlayher/ndp"
)

func listenNDP(iface *net.Interface) (ndpConn, netip.Addr, error) {
	return ndp.Listen(iface, ndp.LinkLocal)
}
