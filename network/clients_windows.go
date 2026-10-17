package network

import (
	"errors"
	"net/netip"

	"golang.org/x/sys/windows"
)

// Windows clients already have a connected LAN return route. Unlike Unix, this
// backend only validates it; it does not install routes or enable forwarding.
type ClientRoutes struct{ iface Interface }

func NewClientRoutes(iface Interface) (*ClientRoutes, error) {
	if iface.Index <= 0 {
		return nil, errors.New("missing Windows LAN interface index")
	}
	return &ClientRoutes{iface}, nil
}

func (c *ClientRoutes) Sync(addresses []netip.Addr) error {
	for _, ip := range addresses {
		if !ip.Is4() {
			return errors.New("Windows client routing currently supports IPv4 only")
		}
		onLink := false
		for _, p := range c.iface.Addresses {
			onLink = onLink || (p.Contains(ip) && p.Addr() != ip)
		}
		if !onLink {
			return errors.New("Windows DHCP client must be on the selected LAN")
		}
		var index uint32
		if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: ip.As4()}, &index); err != nil {
			return err
		}
		if index != uint32(c.iface.Index) {
			return errors.New("Windows client return route does not select the LAN")
		}
	}
	return nil
}

func (*ClientRoutes) Close() error { return nil }
