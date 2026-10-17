package dhcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/UruhaLushia/lantern/device"
	"github.com/UruhaLushia/lantern/discovery"
	"github.com/UruhaLushia/lantern/network"
)

// Run only on an isolated Hyper-V internal switch with two real DHCP clients.
// This exercises DHCP's native transport, not the gateway injection datapath.
func TestWindowsDHCPVirtualLAN(t *testing.T) {
	name := os.Getenv("LANTERN_TEST_DHCP_IFACE")
	if name == "" {
		t.Skip("requires isolated Hyper-V DHCP clients and LANTERN_TEST_DHCP_IFACE")
	}
	if !strings.HasPrefix(name, "vEthernet (lantern-dhcp-") {
		t.Fatal("test requires a dedicated lantern-dhcp-* internal switch")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	local := netip.MustParsePrefix("198.18.79.1/24")
	found := false
	for _, addr := range addresses {
		found = found || addr.String() == local.String()
	}
	if !found {
		t.Fatal("test interface must have 198.18.79.1/24")
	}
	store := device.NewStore(32)
	observer, err := discovery.Start(t.Context(), *iface, discovery.Options{Enabled: true}, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := observer.Close(); err != nil {
			t.Error(err)
		}
	})
	selected := network.Selection{Interface: network.Interface{Name: name, Index: iface.Index, MAC: iface.HardwareAddr.String(), Addresses: []netip.Prefix{local}}, GatewayIPv4: netip.MustParseAddr("198.18.79.254")}
	releases := make(chan string, 16)
	opts := Options{Enabled: true, ExclusivePool: true,
		ServerIP: local.Addr(), Gateway: selected.GatewayIPv4,
		PoolStart: netip.MustParseAddr("198.18.79.100"), PoolEnd: netip.MustParseAddr("198.18.79.101"),
		DNS: []netip.Addr{local.Addr()}, Lease: time.Minute, ObserveWindow: time.Second,
		AllowedMACs: []string{"00:15:5d:79:00:01", "00:15:5d:79:00:02"},
		GatewayMACs: []string{"00:15:5d:79:00:01"}, LeaseFile: filepath.Join(t.TempDir(), "leases.json"),
		Reservations: []Reservation{{MAC: "00:15:5d:79:00:01", IP: netip.MustParseAddr("198.18.79.100")}, {MAC: "00:15:5d:79:00:02", IP: netip.MustParseAddr("198.18.79.101")}}}
	opts.OnLease = func(lease Lease, selected bool) error {
		if selected != (lease.MAC == opts.GatewayMACs[0]) {
			return fmt.Errorf("incorrect gateway selection for %s", lease.MAC)
		}
		if lease.State == "bound" && !lease.ExpiresAt.After(time.Now()) {
			select {
			case releases <- lease.MAC:
			default:
				return fmt.Errorf("too many release notifications")
			}
		}
		return nil
	}
	startServer := func() *Service {
		t.Helper()
		// DHCP-only test: the virtual LAN has no upstream/forwarding service.
		s, err := Start(t.Context(), selected, opts, observer, store, func() error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		})
		return s
	}
	s := startServer()
	wait := func(phase string, ready func(Status) bool) Status {
		t.Helper()
		deadline := time.NewTimer(65 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			status := s.Snapshot()
			if status.LastError != "" || status.PausedReason != "" {
				t.Fatalf("%s: %+v", phase, status)
			}
			if ready(status) {
				data, _ := json.Marshal(status)
				t.Logf("%s: %s", phase, data)
				return status
			}
			select {
			case <-t.Context().Done():
				t.Fatal(context.Cause(t.Context()))
			case <-deadline.C:
				t.Fatalf("%s timed out: DHCP=%+v discovery=%+v", phase, status, observer.Snapshot())
			case <-tick.C:
			}
		}
	}
	bound := func(status Status) bool {
		if len(status.Leases) != 2 {
			return false
		}
		for _, lease := range status.Leases {
			if lease.State != "bound" {
				return false
			}
		}
		return true
	}
	initial := wait("two clients completed DORA", func(status Status) bool { return status.Offers >= 2 && status.ACKs >= 2 && bound(status) })
	expires := make(map[string]time.Time, 2)
	for _, lease := range initial.Leases {
		expires[lease.MAC] = lease.ExpiresAt
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = startServer()
	if !bound(s.Snapshot()) {
		t.Fatal("server restart lost bound leases")
	}
	t.Log("persisted leases restored by a fresh service")
	wait("both clients renewed after server restart", func(status Status) bool {
		if status.ACKs < 2 || !bound(status) {
			return false
		}
		for _, lease := range status.Leases {
			if !lease.ExpiresAt.After(expires[lease.MAC].Add(time.Second)) {
				return false
			}
		}
		return true
	})
	released := make(map[string]bool, 2)
	wait("both clients released leases", func(status Status) bool {
		for {
			select {
			case mac := <-releases:
				released[mac] = true
			default:
				if len(released) != 2 {
					return false
				}
				for _, lease := range status.Leases {
					if lease.ExpiresAt.After(time.Now()) {
						return false
					}
				}
				return true
			}
		}
	})
}
