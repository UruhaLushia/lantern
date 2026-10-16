package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type clientRoute struct {
	route     []byte
	rule      []byte
	ruleAdded bool
}

type ClientRoutes struct {
	conn     *netlink.Conn
	iface    Interface
	table    uint32
	priority uint32
	entries  map[netip.Addr]clientRoute
}

func NewClientRoutes(iface Interface) (_ *ClientRoutes, err error) {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = c.Close()
		}
	}()
	routes, err := clientDump(c, unix.RTM_GETROUTE)
	if err != nil {
		return nil, err
	}
	rules, err := clientDump(c, unix.RTM_GETRULE)
	if err != nil {
		return nil, err
	}
	used := make(map[uint32]bool)
	priority := uint32(1000)
	for _, r := range routes {
		if len(r.Data) < 12 {
			continue
		}
		used[uint32(r.Data[4])] = true
		attrs, err := netlink.UnmarshalAttributes(r.Data[12:])
		if err != nil {
			return nil, err
		}
		for _, a := range attrs {
			if a.Type == unix.RTA_TABLE && len(a.Data) == 4 {
				used[binary.NativeEndian.Uint32(a.Data)] = true
			}
		}
	}
	for _, r := range rules {
		if len(r.Data) < 12 {
			continue
		}
		used[uint32(r.Data[4])] = true
		attrs, err := netlink.UnmarshalAttributes(r.Data[12:])
		if err != nil {
			return nil, err
		}
		for _, a := range attrs {
			if len(a.Data) != 4 {
				continue
			}
			v := binary.NativeEndian.Uint32(a.Data)
			if a.Type == unix.FRA_TABLE {
				used[v] = true
			}
			if a.Type == unix.FRA_PRIORITY && v > 0 && v <= priority {
				priority = v - 1
			}
		}
	}
	if priority == 0 {
		return nil, errors.New("no rule priority available before existing policy routing")
	}
	table := uint32(19478)
	for used[table] && table < 20478 {
		table++
	}
	if used[table] {
		return nil, errors.New("no unused client routing table available")
	}
	return &ClientRoutes{conn: c, iface: iface, table: table, priority: priority, entries: make(map[netip.Addr]clientRoute)}, nil
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
	var errs []error
	for ip := range c.entries {
		if !want[ip] {
			errs = append(errs, c.remove(ip))
		}
	}
	for ip := range want {
		if _, ok := c.entries[ip]; ok {
			continue
		}
		family, bits := uint8(unix.AF_INET6), uint8(128)
		if ip.Is4() {
			family, bits = unix.AF_INET, 32
		}
		dst := net.IP(ip.AsSlice())
		route, err := clientMessage([]byte{family, bits, 0, 0, 0, unix.RTPROT_STATIC, unix.RT_SCOPE_LINK, unix.RTN_UNICAST, 0, 0, 0, 0},
			netlink.Attribute{Type: unix.RTA_DST, Data: dst},
			netlink.Attribute{Type: unix.RTA_OIF, Data: clientUint32(uint32(c.iface.Index))},
			netlink.Attribute{Type: unix.RTA_TABLE, Data: clientUint32(c.table)})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rule, err := clientMessage([]byte{family, bits, 0, 0, 0, 0, 0, unix.FR_ACT_TO_TBL, 0, 0, 0, 0},
			netlink.Attribute{Type: unix.FRA_DST, Data: dst},
			netlink.Attribute{Type: unix.FRA_TABLE, Data: clientUint32(c.table)},
			netlink.Attribute{Type: unix.FRA_PRIORITY, Data: clientUint32(c.priority)})
		if err != nil {
			errs = append(errs, err)
			continue
		}

		if err := clientChange(c.conn, unix.RTM_NEWROUTE, route, true); err != nil {
			errs = append(errs, fmt.Errorf("client route %s: %w", ip, err))
			continue
		}
		c.entries[ip] = clientRoute{route: route, rule: rule}
		if err := clientChange(c.conn, unix.RTM_NEWRULE, rule, true); err != nil {
			errs = append(errs, fmt.Errorf("client rule %s: %w", ip, err), c.remove(ip))
		} else {
			c.entries[ip] = clientRoute{route: route, rule: rule, ruleAdded: true}
		}
	}
	return errors.Join(errs...)
}

func missingRoute(err error) bool {
	return err == nil || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH)
}

func (c *ClientRoutes) remove(ip netip.Addr) error {
	e := c.entries[ip]
	if e.ruleAdded {
		if err := clientChange(c.conn, unix.RTM_DELRULE, e.rule, false); !missingRoute(err) {
			return err
		}
		e.ruleAdded = false
		c.entries[ip] = e
	}
	if err := clientChange(c.conn, unix.RTM_DELROUTE, e.route, false); !missingRoute(err) {
		return err
	}
	delete(c.entries, ip)
	return nil
}

func (c *ClientRoutes) Close() error {
	err := c.Sync(nil)
	if err != nil {
		return err
	}
	return c.conn.Close()
}

func clientUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}
func clientMessage(header []byte, attrs ...netlink.Attribute) ([]byte, error) {
	b, err := netlink.MarshalAttributes(attrs)
	return append(header, b...), err
}
func clientDump(c *netlink.Conn, kind uint16) ([]netlink.Message, error) {
	return c.Execute(netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(kind), Flags: netlink.Request | netlink.Dump}, Data: make([]byte, 12)})
}
func clientChange(c *netlink.Conn, kind uint16, data []byte, add bool) error {
	flags := netlink.Request | netlink.Acknowledge
	if add {
		flags |= netlink.Create | netlink.Excl
	}
	_, err := c.Execute(netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(kind), Flags: flags}, Data: data})
	return err
}
