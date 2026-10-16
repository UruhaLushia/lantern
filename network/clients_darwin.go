package network

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

type ClientRoutes struct {
	fd      int
	seq     int
	iface   Interface
	entries map[netip.Addr]bool
}

func NewClientRoutes(iface Interface) (*ClientRoutes, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &ClientRoutes{fd: fd, iface: iface, entries: make(map[netip.Addr]bool)}, nil
}

func (c *ClientRoutes) Sync(addresses []netip.Addr) error {
	want := make(map[netip.Addr]bool, len(addresses))
	for _, ip := range addresses {
		ip = ip.WithZone("")
		if !ip.IsGlobalUnicast() || ip.Is4In6() {
			continue
		}
		for _, prefix := range c.iface.Addresses {
			if prefix.Contains(ip) && prefix.Addr() != ip {
				want[ip] = true
				break
			}
		}
	}
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return err
	}
	existing := make(map[netip.Addr]*route.RouteMessage)
	for _, msg := range messages {
		m, ok := msg.(*route.RouteMessage)
		if !ok || m.Err != nil || m.Flags&unix.RTF_HOST == 0 || m.Flags&unix.RTF_IFSCOPE != 0 || len(m.Addrs) <= unix.RTAX_DST {
			continue
		}
		ip := routeAddr(m.Addrs[unix.RTAX_DST])
		if ip.IsValid() {
			existing[ip] = m
		}
	}
	var errs []error
	for ip, owned := range c.entries {
		if want[ip] {
			continue
		}
		if m := existing[ip]; owned && c.direct(m) && m.Flags&unix.RTF_PROTO1 != 0 {
			if err := c.change(ip, unix.RTM_DELETE); err != nil && !errors.Is(err, unix.ESRCH) {
				errs = append(errs, fmt.Errorf("remove client route %s: %w", ip, err))
				continue
			}
		}
		delete(c.entries, ip)
	}
	for ip := range want {
		if m := existing[ip]; m != nil {
			if !c.direct(m) {
				errs = append(errs, fmt.Errorf("client route %s already belongs to another interface or gateway", ip))
			} else if _, tracked := c.entries[ip]; !tracked {
				c.entries[ip] = false
			}
			continue
		}
		if err := c.change(ip, unix.RTM_ADD); err != nil {
			errs = append(errs, fmt.Errorf("add client route %s: %w", ip, err))
		} else {
			c.entries[ip] = true
		}
	}
	return errors.Join(errs...)
}

func (c *ClientRoutes) direct(m *route.RouteMessage) bool {
	return m != nil && m.Index == c.iface.Index && m.Flags&unix.RTF_UP != 0 &&
		m.Flags&(unix.RTF_GATEWAY|unix.RTF_REJECT|unix.RTF_BLACKHOLE) == 0
}

func (c *ClientRoutes) change(ip netip.Addr, kind int) error {
	var dst route.Addr
	if ip.Is4() {
		dst = &route.Inet4Addr{IP: ip.As4()}
	} else {
		dst = &route.Inet6Addr{IP: ip.As16()}
	}
	c.seq++
	m := route.RouteMessage{Version: unix.RTM_VERSION, Type: kind,
		Flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_STATIC | unix.RTF_PROTO1,
		Index: c.iface.Index, ID: uintptr(os.Getpid()), Seq: c.seq,
		Addrs: []route.Addr{unix.RTAX_DST: dst, unix.RTAX_GATEWAY: &route.LinkAddr{Index: c.iface.Index, Name: c.iface.Name}}}
	b, err := m.Marshal()
	if err != nil {
		return err
	}
	if _, err := unix.Write(c.fd, b); err != nil {
		return err
	}
	buf := make([]byte, 64<<10)
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		n, err := unix.Read(c.fd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
		if err != nil {
			return err
		}
		for _, msg := range messages {
			if reply, ok := msg.(*route.RouteMessage); ok && reply.ID == m.ID && reply.Seq == m.Seq && reply.Type == kind {
				return reply.Err
			}
		}
	}
	return os.ErrDeadlineExceeded
}

func (c *ClientRoutes) Close() error {
	if err := c.Sync(nil); err != nil {
		return err
	}
	return unix.Close(c.fd)
}
