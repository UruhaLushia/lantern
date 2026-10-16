//go:build linux || darwin

package announce

import (
	"context"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/UruhaLushia/lantern/discovery"
	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/mdlayher/ndp"
)

func TestRAAdvertisementAndWithdrawal(t *testing.T) {
	if os.Getenv("LANTERN_TEST_IFACE") == "" || os.Getenv("LANTERN_TEST_PEER") == "" {
		t.Skip("requires a virtual Ethernet pair")
	}
	peer, err := net.InterfaceByName(os.Getenv("LANTERN_TEST_PEER"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ether.Listen(peer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := c.JoinGroup(net.HardwareAddr{0x33, 0x33, 0, 0, 0, 1}); err != nil {
		t.Fatal(err)
	}
	iface, err := net.InterfaceByName(os.Getenv("LANTERN_TEST_IFACE"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Start(context.Background(), *iface, Options{Enabled: true, MinInterval: 3 * time.Second, MaxInterval: 4 * time.Second, Lifetime: 12 * time.Second}, func() Upstream {
		return Upstream{Ready: true, Router: discovery.Router{Address: netip.MustParseAddr("fe80::77:2"), ExpiresAt: time.Now().Add(time.Minute)}}
	})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = s.Close()
		}
	})
	readRA := func(lifetime time.Duration) {
		t.Helper()
		if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 4096)
		for {
			n, _, err := c.ReadFrom(b)
			if err != nil {
				t.Fatalf("RA: %v; status: %+v", err, s.Snapshot())
			}
			f, err := ether.Parse(b[:n])
			if err != nil || !slices.Equal(f.SourceMAC, iface.HardwareAddr) {
				continue
			}
			d, err := ether.IP(f)
			if err != nil || d.Protocol != 58 || !ether.ICMPv6Valid(d) {
				continue
			}
			msg, err := ndp.ParseMessage(d.Payload)
			ra, ok := msg.(*ndp.RouterAdvertisement)
			if err != nil || !ok {
				continue
			}
			if d.HopLimit != 255 || !d.Source.IsLinkLocalUnicast() || ra.RouterSelectionPreference != ndp.High || ra.RouterLifetime != lifetime {
				t.Fatalf("unexpected RA: %+v, datagram: %+v", ra, d)
			}
			return
		}
	}
	readRA(12 * time.Second)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	readRA(0)
}
