package network

import (
	"net/netip"
	"os"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

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
