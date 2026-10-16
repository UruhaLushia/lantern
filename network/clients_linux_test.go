package network

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"testing"
)

func TestLinuxClientRouteLifecycle(t *testing.T) {
	if os.Getenv("LANTERN_TEST_IFACE") == "" {
		t.Skip("requires a virtual LAN interface")
	}
	snapshot, err := Discover()
	if err != nil {
		t.Fatal(err)
	}
	selected, err := snapshot.Select(os.Getenv("LANTERN_TEST_IFACE"), netip.MustParseAddr("198.18.77.2"), netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	command := func(args ...string) []byte {
		t.Helper()
		b, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, b)
		}
		return b
	}
	before4, before6 := command("-j", "rule", "show"), command("-6", "-j", "rule", "show")
	routes, err := NewClientRoutes(selected.Interface)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := routes.Close(); err != nil {
			t.Error(err)
		}
	})
	ips := []netip.Addr{netip.MustParseAddr("198.18.77.99"), netip.MustParseAddr("fd00:77::99")}
	if err := routes.Sync(ips); err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		var found []struct {
			Dev   string `json:"dev"`
			Table any    `json:"table"`
		}
		if err := json.Unmarshal(command("-j", "route", "get", ip.String()), &found); err != nil {
			t.Fatal(err)
		}
		if len(found) != 1 || found[0].Dev != selected.Interface.Name || found[0].Table == nil || found[0].Table == "main" {
			t.Fatalf("client %s did not use the dedicated LAN table: %+v", ip, found)
		}
	}
	if err := routes.Sync(nil); err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		var found []json.RawMessage
		if err := json.Unmarshal(command("-j", "route", "show", "table", "all", "exact", ip.String()), &found); err != nil {
			t.Fatal(err)
		}
		if len(found) != 0 {
			t.Fatalf("client route %s was left behind: %s", ip, found)
		}
	}
	if !bytes.Equal(before4, command("-j", "rule", "show")) || !bytes.Equal(before6, command("-6", "-j", "rule", "show")) {
		t.Fatal("policy routing rules were not restored")
	}
}
