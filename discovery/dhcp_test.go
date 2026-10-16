//go:build linux || darwin

package discovery

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/UruhaLushia/lantern/network"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/mdlayher/packet"
)

var (
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
func TestDHCPProbe(t *testing.T) {
	selected, peer, c := testLink(t)
	responded := make(chan error, 1)
	go func() {
		request, err := readDHCP(c, time.Now().Add(5*time.Second), func(p *dhcpv4.DHCPv4) bool {
			return p.MessageType() == dhcpv4.MessageTypeDiscover
		})
		if err == nil {
			var offer *dhcpv4.DHCPv4
			offer, err = dhcpv4.NewReplyFromRequest(request,
				dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer), dhcpv4.WithYourIP(poolStart.AsSlice()),
				dhcpv4.WithOption(dhcpv4.OptServerIdentifier(routerIP.AsSlice())),
				dhcpv4.WithOption(dhcpv4.OptRouter(routerIP.AsSlice())))
			if err == nil {
				// A repeated offer from one server must not appear as two conflicts.
				err = errors.Join(sendDHCP(c, peer.HardwareAddr, routerIP, offer), sendDHCP(c, peer.HardwareAddr, routerIP, offer))
			}
		}
		responded <- err
	}()
	result, err := ProbeDHCP(t.Context(), selected.Interface.Name, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-responded; err != nil {
		t.Fatal(err)
	}
	if result.DiscoveriesSent != 2 || len(result.Servers) != 1 || result.Servers[0].Address != routerIP || result.Servers[0].MAC != peer.HardwareAddr.String() {
		t.Fatalf("unexpected DHCP probe: %+v", result)
	}
}
