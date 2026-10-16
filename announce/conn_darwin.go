package announce

import (
	"net"
	"net/netip"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

type darwinNDPConn struct {
	*ndp.Conn
	iface *net.Interface
}

func listenNDP(iface *net.Interface) (ndpConn, netip.Addr, error) {
	c, src, err := ndp.Listen(iface, ndp.LinkLocal)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	return &darwinNDPConn{Conn: c, iface: iface}, src, nil
}

func (c *darwinNDPConn) WriteTo(m ndp.Message, cm *ipv6.ControlMessage, dst netip.Addr) error {
	if cm == nil {
		// The socket is already bound to the link-local source.
		cm = &ipv6.ControlMessage{HopLimit: ndp.HopLimit, IfIndex: c.iface.Index}
	}
	return c.Conn.WriteTo(m, cm, dst)
}
