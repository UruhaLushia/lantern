//go:build linux || darwin

package lantern

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/UruhaLushia/lantern/discovery"
)

func TestControllerStop(t *testing.T) {
	name := os.Getenv("LANTERN_TEST_IFACE")
	if name == "" {
		t.Skip("requires a virtual LAN interface")
	}
	c, err := New(Options{Interface: name, GatewayIPv4: netip.MustParseAddr("198.18.77.2"),
		Discovery: discovery.Options{Enabled: true}, PollInterval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	if status := c.Status(); !status.Discovery.Running {
		t.Fatalf("discovery did not start: %+v", status)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.Done():
	default:
		t.Fatal("controller did not terminate")
	}
	if status := c.Status(); status.Discovery.Running || status.DHCP.Running || status.RA.Enabled {
		t.Fatalf("resources survived controller shutdown: %+v", status)
	}
}
