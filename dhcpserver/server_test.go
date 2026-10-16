//go:build linux || darwin

package dhcpserver

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/UruhaLushia/lantern/device"
	"github.com/UruhaLushia/lantern/discovery"
	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/UruhaLushia/lantern/network"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/mdlayher/packet"
)

var (
	serverIP  = netip.MustParseAddr("198.18.77.1")
	routerIP  = netip.MustParseAddr("198.18.77.2")
	poolStart = netip.MustParseAddr("198.18.77.5")
	broadcast = net.HardwareAddr{255, 255, 255, 255, 255, 255}
)

func testLink(t *testing.T) (network.Selection, *net.Interface, ether.Socket) {
	t.Helper()
	name, peerName := os.Getenv("LANTERN_TEST_IFACE"), os.Getenv("LANTERN_TEST_PEER")
	if name == "" || peerName == "" {
		t.Skip("requires a virtual Ethernet pair")
	}
	peer, err := net.InterfaceByName(peerName)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := network.Discover()
	if err != nil {
		t.Fatal(err)
	}
	selected, err := snapshot.Select(name, routerIP, netip.Addr{})
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
	return selected, peer, c
}

func sendDHCP(c ether.Socket, mac net.HardwareAddr, source netip.Addr, p *dhcpv4.DHCPv4) error {
	src, dst := uint16(68), uint16(67)
	if p.OpCode == dhcpv4.OpcodeBootReply {
		src, dst = dst, src
	}
	b, err := ether.IPv4UDP(mac, broadcast, source, netip.MustParseAddr("255.255.255.255"), src, dst, p.ToBytes())
	if err != nil {
		return err
	}
	_, err = c.WriteTo(b, &packet.Addr{HardwareAddr: broadcast})
	return err
}

func readDHCP(c ether.Socket, deadline time.Time, accept func(*dhcpv4.DHCPv4) bool) (*dhcpv4.DHCPv4, error) {
	if err := c.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	b := make([]byte, 4096)
	for {
		n, _, err := c.ReadFrom(b)
		if err != nil {
			return nil, err
		}
		f, err := ether.Parse(b[:n])
		if err != nil {
			continue
		}
		d, err := ether.IP(f)
		if err != nil {
			continue
		}
		d, err = ether.UDP(d)
		if err != nil || d.SourcePort != 67 && d.SourcePort != 68 {
			continue
		}
		p, err := dhcpv4.FromBytes(slices.Clone(d.Payload))
		if err == nil && accept(p) {
			return p, nil
		}
	}
}
func TestDHCPLeaseAndTakeover(t *testing.T) {
	selected, peer, c := testLink(t)
	iface, err := net.InterfaceByIndex(selected.Interface.Index)
	if err != nil {
		t.Fatal(err)
	}
	store := device.NewStore(32)
	observer, err := discovery.Start(t.Context(), *iface, discovery.Options{Enabled: true, MDNS: true, SSDP: true}, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := observer.Close(); err != nil {
			t.Error(err)
		}
	})
	s, err := Start(t.Context(), selected, Options{
		Enabled: true, ExclusivePool: true, ServerIP: serverIP, Gateway: routerIP,
		PoolStart: poolStart, PoolEnd: netip.MustParseAddr("198.18.77.20"),
		DNS:       []netip.Addr{netip.MustParseAddr("223.5.5.5"), netip.MustParseAddr("223.6.6.6")},
		LeaseFile: t.TempDir() + "/leases.json", ObserveWindow: time.Second,
	}, observer, store, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	time.Sleep(time.Until(s.Snapshot().ObservingUntil) + 20*time.Millisecond)
	discover, err := dhcpv4.NewDiscovery(peer.HardwareAddr, dhcpv4.WithOption(dhcpv4.OptHostName("ci-client")))
	if err != nil {
		t.Fatal(err)
	}
	discover.SetBroadcast()
	if err := sendDHCP(c, peer.HardwareAddr, netip.IPv4Unspecified(), discover); err != nil {
		t.Fatal(err)
	}
	offer, err := readDHCP(c, time.Now().Add(5*time.Second), func(p *dhcpv4.DHCPv4) bool {
		return p.TransactionID == discover.TransactionID && p.MessageType() == dhcpv4.MessageTypeOffer
	})
	if err != nil {
		t.Fatalf("offer: %v; DHCP: %+v", err, s.Snapshot())
	}
	request, err := dhcpv4.NewRequestFromOffer(offer, dhcpv4.WithOption(dhcpv4.OptHostName("ci-client")))
	if err != nil {
		t.Fatal(err)
	}
	request.SetBroadcast()
	for _, takeover := range []bool{false, true, false} {
		macs := []string{}
		wantGateway := routerIP
		if takeover {
			macs, wantGateway = []string{peer.HardwareAddr.String()}, serverIP
		}
		if err := s.SetGatewayMACs(macs); err != nil {
			t.Fatal(err)
		}
		if err := sendDHCP(c, peer.HardwareAddr, netip.IPv4Unspecified(), request); err != nil {
			t.Fatal(err)
		}
		ack, err := readDHCP(c, time.Now().Add(5*time.Second), func(p *dhcpv4.DHCPv4) bool {
			return p.TransactionID == request.TransactionID && p.MessageType() == dhcpv4.MessageTypeAck
		})
		if err != nil {
			t.Fatalf("ACK: %v; DHCP: %+v", err, s.Snapshot())
		}
		if len(ack.Router()) != 1 || !ack.Router()[0].Equal(wantGateway.AsSlice()) || !ack.YourIPAddr.Equal(poolStart.AsSlice()) || len(ack.DNS()) != 2 {
			t.Fatalf("takeover=%v, unexpected ACK: %s", takeover, ack.Summary())
		}
	}
	leases := s.Snapshot().Leases
	if len(leases) != 1 || leases[0].State != "bound" || leases[0].Hostname != "ci-client" {
		t.Fatalf("missing DHCP device metadata: %+v", leases)
	}
	foreign, err := dhcpv4.NewReplyFromRequest(request,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer), dhcpv4.WithYourIP(poolStart.AsSlice()),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(routerIP.AsSlice())))
	if err != nil {
		t.Fatal(err)
	}
	if err := sendDHCP(c, peer.HardwareAddr, routerIP, foreign); err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(time.Second)
	for s.Snapshot().PausedReason == "" && time.Now().Before(end) {
		time.Sleep(10 * time.Millisecond)
	}
	if status := s.Snapshot(); status.PausedReason == "" || status.Conflicts != 1 {
		t.Fatalf("foreign DHCP did not pause allocation: %+v", status)
	}
	blocked, err := dhcpv4.NewDiscovery(peer.HardwareAddr)
	if err != nil {
		t.Fatal(err)
	}
	if err := sendDHCP(c, peer.HardwareAddr, netip.IPv4Unspecified(), blocked); err != nil {
		t.Fatal(err)
	}
	_, err = readDHCP(c, time.Now().Add(300*time.Millisecond), func(p *dhcpv4.DHCPv4) bool {
		return p.TransactionID == blocked.TransactionID && p.OpCode == dhcpv4.OpcodeBootReply
	})
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("paused server replied or failed unexpectedly: %v", err)
	}
	if err := s.Resume(); err != nil {
		t.Fatal(err)
	}
	if status := s.Snapshot(); status.PausedReason != "" || !status.ObservingUntil.After(time.Now()) {
		t.Fatalf("resume must restart the observation window: %+v", status)
	}
}
