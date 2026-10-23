package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestClientRouteAddRace(t *testing.T) {
	const index = 7
	ip := netip.MustParseAddr("192.0.2.99")
	for _, tt := range []struct {
		name  string
		index int
		flags int
		dst   netip.Addr
		valid bool
	}{
		{"direct LAN", index, unix.RTF_UP | unix.RTF_HOST, ip, true},
		{"borrow another owner", index, unix.RTF_UP | unix.RTF_HOST | unix.RTF_PROTO1, ip, true},
		{"other interface", index + 1, unix.RTF_UP | unix.RTF_HOST, ip, false},
		{"gateway", index, unix.RTF_UP | unix.RTF_HOST | unix.RTF_GATEWAY, ip, false},
		{"reject", index, unix.RTF_UP | unix.RTF_HOST | unix.RTF_REJECT, ip, false},
		{"blackhole", index, unix.RTF_UP | unix.RTF_HOST | unix.RTF_BLACKHOLE, ip, false},
		{"scoped", index, unix.RTF_UP | unix.RTF_HOST | unix.RTF_IFSCOPE, ip, false},
		{"network route", index, unix.RTF_UP, netip.MustParseAddr("192.0.2.0"), false},
		{"other host", index, unix.RTF_UP | unix.RTF_HOST, netip.MustParseAddr("192.0.2.100"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, fd := range fds {
				t.Cleanup(func() { _ = unix.Close(fd) })
				if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() {
				buf := make([]byte, 64<<10)
				for _, kind := range []int{unix.RTM_ADD, unix.RTM_GET} {
					n, err := unix.Read(fds[1], buf)
					if err != nil {
						done <- err
						return
					}
					msgs, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
					if err != nil || len(msgs) != 1 {
						done <- fmt.Errorf("parse request: %v (%d messages)", err, len(msgs))
						return
					}
					m := msgs[0].(*route.RouteMessage)
					if m.Type != kind || m.Flags&unix.RTF_IFSCOPE != 0 || len(m.Addrs) <= unix.RTAX_IFP {
						done <- fmt.Errorf("unexpected route request: %+v", m)
						return
					}
					if kind == unix.RTM_GET {
						m.Index, m.Flags = tt.index, tt.flags
						m.Addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: tt.dst.As4()}
					}
					reply, err := m.Marshal()
					if err == nil {
						if kind == unix.RTM_ADD {
							binary.NativeEndian.PutUint32(reply[28:32], uint32(unix.EEXIST))
						}
						_, err = unix.Write(fds[1], reply)
					}
					if err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			c := ClientRoutes{fd: fds[0], iface: Interface{Index: index, Name: "en0"}}
			owned, err := c.add(ip)
			if owned || (err == nil) != tt.valid || (!tt.valid && !errors.Is(err, unix.EEXIST)) {
				t.Errorf("add: owned=%v, err=%v; valid=%v", owned, err, tt.valid)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDarwinDefaultRouteSelection(t *testing.T) {
	iface := net.Interface{Index: 7, Name: "en0"}
	makeRoute := func(gateway string, flags, zone int) *route.RouteMessage {
		ip := netip.MustParseAddr(gateway)
		return &route.RouteMessage{Index: iface.Index, Flags: unix.RTF_UP | unix.RTF_GATEWAY | flags,
			Addrs: []route.Addr{
				unix.RTAX_DST:     &route.Inet6Addr{},
				unix.RTAX_GATEWAY: &route.Inet6Addr{IP: ip.As16(), ZoneID: zone},
				unix.RTAX_NETMASK: &route.Inet6Addr{},
			}}
	}
	for _, tt := range []struct {
		name string
		m    *route.RouteMessage
	}{
		{"host route to unspecified", makeRoute("fe80::5", unix.RTF_HOST, 7)},
		{"wrong gateway scope", makeRoute("fe80::5", 0, 8)},
		{"unspecified gateway", makeRoute("::", 0, 0)},
		{"multicast gateway", makeRoute("ff02::1", 0, 0)},
		{"loopback gateway", makeRoute("::1", 0, 0)},
		{"rejected route", makeRoute("fe80::5", unix.RTF_REJECT, 7)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if r, ok := darwinDefaultRoute(tt.m, iface); ok {
				t.Fatalf("invalid default route accepted: %+v", r)
			}
		})
	}
	s := Snapshot{Interfaces: []Interface{{Index: iface.Index, Name: iface.Name, LANCapable: true,
		Addresses: []netip.Prefix{netip.MustParsePrefix("fe80::10/64")}}}}
	for _, m := range []*route.RouteMessage{
		makeRoute("fe80::1", unix.RTF_IFSCOPE, iface.Index),
		makeRoute("fe80::1", 0, iface.Index),
	} {
		r, ok := darwinDefaultRoute(m, iface)
		if !ok {
			t.Fatal("valid default route rejected")
		}
		s.DefaultRoutes = append(s.DefaultRoutes, r)
	}
	selection, err := s.Select(iface.Name, netip.Addr{}, netip.Addr{})
	if err != nil || selection.GatewayIPv6.String() != "fe80::1%en0" {
		t.Fatalf("selection=%+v, err=%v", selection, err)
	}
	// Equal-priority alternatives must remain ambiguous, not depend on RIB order.
	s.DefaultRoutes = append(s.DefaultRoutes, Route{Interface: iface.Name, Gateway: netip.MustParseAddr("fe80::5%en0")})
	if _, err := s.Select(iface.Name, netip.Addr{}, netip.Addr{}); err == nil {
		t.Fatal("ambiguous upstreams accepted")
	}
}

func TestClientRouteLifecycle(t *testing.T) {
	name := os.Getenv("LANTERN_TEST_IFACE")
	if name == "" {
		t.Skip("requires a virtual LAN interface")
	}
	snapshot, err := Discover()
	if err != nil {
		t.Fatal(err)
	}
	selected, err := snapshot.Select(name, netip.MustParseAddr("198.18.77.2"), netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	newRoutes := func() *ClientRoutes {
		t.Helper()
		c, err := NewClientRoutes(selected.Interface)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		})
		return c
	}
	ips := []netip.Addr{netip.MustParseAddr("198.18.77.99"), netip.MustParseAddr("fd00:77::99")}
	check := func(present bool) {
		t.Helper()
		rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
		if err != nil {
			t.Fatal(err)
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
		if err != nil {
			t.Fatal(err)
		}
		for _, ip := range ips {
			found := false
			for _, msg := range messages {
				m, ok := msg.(*route.RouteMessage)
				if !ok || len(m.Addrs) <= unix.RTAX_DST || m.Flags&unix.RTF_HOST == 0 || routeAddr(m.Addrs[unix.RTAX_DST]) != ip {
					continue
				}
				if m.Index != selected.Interface.Index || m.Flags&unix.RTF_PROTO1 == 0 || m.Flags&unix.RTF_GATEWAY != 0 {
					t.Fatalf("unexpected route for %s: %+v", ip, m)
				}
				found = true
			}
			if found != present {
				t.Fatalf("route for %s: present=%v, want %v", ip, found, present)
			}
		}
	}
	owner, borrower := newRoutes(), newRoutes()
	if err := owner.Sync(ips); err != nil {
		t.Fatal(err)
	}
	check(true)
	if err := borrower.Sync(ips); err != nil {
		t.Fatal(err)
	}
	if err := borrower.Sync(nil); err != nil {
		t.Fatal(err)
	}
	check(true)
	if err := owner.Sync(nil); err != nil {
		t.Fatal(err)
	}
	check(false)
}
