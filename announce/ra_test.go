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

	"github.com/UruhaLushia/lantern/device"
	"github.com/UruhaLushia/lantern/discovery"
	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

func TestRAAdvertisementAndWithdrawal(t *testing.T) {
	t.Run("multicast", func(t *testing.T) { testRAAdvertisementAndWithdrawal(t, false) })
	t.Run("unicast", func(t *testing.T) { testRAAdvertisementAndWithdrawal(t, true) })
}

func testRAAdvertisementAndWithdrawal(t *testing.T, unicast bool) {
	t.Helper()
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
	for _, group := range []net.HardwareAddr{{0x33, 0x33, 0, 0, 0, 1}, {0x33, 0x33, 0, 0, 0, 2}} {
		if err := c.JoinGroup(group); err != nil {
			t.Fatal(err)
		}
	}
	iface, err := net.InterfaceByName(os.Getenv("LANTERN_TEST_IFACE"))
	if err != nil {
		t.Fatal(err)
	}
	upstream, source, err := ndp.Listen(peer, ndp.LinkLocal)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	observer, err := discovery.Start(t.Context(), *iface, discovery.Options{Enabled: true}, device.NewStore(16))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = observer.Close() })
	s, err := Start(context.Background(), *iface, Options{Enabled: true, UnicastOnly: unicast, MinInterval: 3 * time.Second, MaxInterval: 4 * time.Second, Lifetime: 12 * time.Second}, func() Upstream {
		for _, router := range observer.Snapshot().Routers {
			if router.Address.WithZone("") == source.WithZone("") {
				return Upstream{Ready: true, Router: router}
			}
		}
		return Upstream{Router: discovery.Router{Address: source}, Reason: "waiting for upstream RA"}
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
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4096)
	for {
		n, _, err := c.ReadFrom(b)
		if err != nil {
			t.Fatalf("upstream RS: %v; status: %+v", err, s.Snapshot())
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
		if _, ok := msg.(*ndp.RouterAdvertisement); ok {
			t.Fatal("advertised before receiving an upstream RA")
		}
		if _, ok := msg.(*ndp.RouterSolicitation); err != nil || !ok {
			continue
		}
		if d.HopLimit != 255 || !d.Source.IsLinkLocalUnicast() || d.Destination != netip.MustParseAddr("ff02::2") {
			t.Fatalf("unexpected upstream RS: %+v", d)
		}
		break
	}
	if err := upstream.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := upstream.WriteTo(&ndp.RouterAdvertisement{RouterLifetime: time.Minute},
		&ipv6.ControlMessage{HopLimit: 255, IfIndex: peer.Index}, netip.MustParseAddr("ff02::1")); err != nil {
		t.Fatal(err)
	}
	if unicast {
		deadline := time.Now().Add(3 * time.Second)
		for len(observer.Snapshot().Routers) == 0 || s.Snapshot().SuspendedReason != "" {
			if time.Now().After(deadline) {
				t.Fatalf("waiting status survived upstream recovery without clients: %+v", s.Snapshot())
			}
			time.Sleep(10 * time.Millisecond)
		}
		if status := s.Snapshot(); status.Advertising || status.Sent != 0 {
			t.Fatalf("advertised without selected clients: %+v", status)
		}
		s.SetTargets([]netip.Addr{source.WithZone("")})
	}
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
			destination := netip.MustParseAddr("ff02::1")
			if unicast {
				destination = source.WithZone("")
			}
			if d.HopLimit != 255 || !d.Source.IsLinkLocalUnicast() || d.Destination != destination || ra.RouterSelectionPreference != ndp.High || ra.RouterLifetime != lifetime {
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
