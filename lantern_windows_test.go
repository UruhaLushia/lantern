package lantern

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestWindowsGatewayRequiresExplicitOptIn(t *testing.T) {
	c, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(t.Context()); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("unverified Windows gateway must not start: %v", err)
	}
	if s := c.Status(); s.State != "idle" || s.DHCP.Running || s.RA.Enabled || s.Discovery.Running {
		t.Fatalf("rejected start changed lifecycle: %+v", s)
	}
}

func TestWindowsRejectsRAWithoutOpeningDatapath(t *testing.T) {
	opts := Options{WindowsGateway: &WindowsGatewayOptions{LocalIPv4: netip.MustParseAddr("198.18.77.1"), EgressInterface: "missing-test-egress"}}
	opts.Discovery.Enabled = true
	opts.RA.Enabled = true
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(t.Context()); err == nil || !strings.Contains(err.Error(), "IPv4 only") {
		t.Fatalf("unsupported RA entered Windows startup: %v", err)
	}
	if c.Status().State != "idle" {
		t.Fatal("rejected startup changed controller state")
	}
}

func TestWindowsConfigureRejectsRAWithoutReconciling(t *testing.T) {
	opts := Options{WindowsGateway: &WindowsGatewayOptions{LocalIPv4: netip.MustParseAddr("198.18.77.1"), EgressInterface: "missing-test-egress"}}
	opts.Discovery.Enabled = true
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	// Represent a started controller without launching any native backend.
	c.started = true
	before := c.Status()
	config := GatewayOptions{}
	config.RA.Enabled = true
	err = c.ConfigureGateway(config)
	if err == nil || !strings.Contains(err.Error(), "IPv4 only") {
		t.Fatalf("unsupported live RA configuration accepted: %v", err)
	}
	if c.opts.RA.Enabled || c.datapath != nil || c.Status().UpdatedAt != before.UpdatedAt {
		t.Fatal("rejected configuration mutated resources or reconciled the network")
	}
}
