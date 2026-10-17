package discovery

import (
	"net"
	"net/netip"
	"testing"

	"github.com/UruhaLushia/lantern/device"
	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

func TestNativeDHCPHasNoInventedEthernetIdentity(t *testing.T) {
	local := netip.MustParseAddr("198.18.77.1")
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	p, err := dhcpv4.NewDiscovery(mac)
	if err != nil { t.Fatal(err) }
	frame, err := ether.IPv4UDP(mac, net.HardwareAddr{255,255,255,255,255,255}, netip.IPv4Unspecified(), netip.MustParseAddr("255.255.255.255"), 68, 67, p.ToBytes())
	if err != nil { t.Fatal(err) }
	s := &Service{iface: net.Interface{Name:"isolated-test"}, store:device.NewStore(8)}
	called := 0
	s.SetDHCPHandler(func(e DHCPEvent) {
		called++
		if !e.LinkAddressUnavailable || len(e.SourceMAC) != 0 || e.Packet.ClientHWAddr.String() != mac.String() {
			t.Fatalf("fabricated wire MAC: %+v", e)
		}
	})
	s.processNativeIPv4(frame[14:], local)
	if called != 1 { t.Fatal("native DHCP discovery was not delivered") }
	for n := 0; n < len(frame)-14; n++ { s.processNativeIPv4(frame[14:14+n],local) }
	if called != 1 { t.Fatal("truncated native packet reached DHCP") }
}
