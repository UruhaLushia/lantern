package wingateway

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"

	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/UruhaLushia/lantern/network"
)

func testClientIP() netip.Addr {
	return netip.MustParseAddr("198.18.77.2")
}

func prepareIPv4(p []byte, client netip.Addr) ([]byte, error) {
	return prepareIPv4Into(nil, p, client)
}

func testPacket(t testing.TB) []byte {
	t.Helper()
	return testUDPPacket(t, testClientIP(), []byte("probe"))
}

func testUDPPacket(t testing.TB, source netip.Addr, payload []byte) []byte {
	t.Helper()
	mac := []byte{2, 0, 0, 0, 0, 1}
	packet, err := ether.IPv4UDP(mac, mac, source, netip.MustParseAddr("162.159.200.1"), 12345, 123, payload)
	if err != nil {
		t.Fatal(err)
	}
	return packet[14:]
}

func TestLiveTUNRouteGuard(t *testing.T) {
	name := os.Getenv("LANTERN_TEST_TUN_IFACE")
	if name == "" {
		t.Skip("requires an explicitly selected existing TUN; reads settings only")
	}
	tun, err := network.InspectWindowsInterface(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"1.1.1.1", "162.159.200.1"} {
		if err := verifyTUNRoute(tun, netip.MustParseAddr(target)); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyTUNRoute(tun, netip.MustParseAddr("127.0.0.1")); err == nil {
		t.Fatal("route through another interface accepted")
	}
	tun.GUID = "{00000000-0000-0000-0000-000000000000}"
	if err := verifyTUNRoute(tun, netip.MustParseAddr("1.1.1.1")); err == nil {
		t.Fatal("changed TUN identity accepted")
	}
}

func TestPacketKeepsSourceAndRepairsOffloadChecksums(t *testing.T) {
	packet := testPacket(t)
	packet[10], packet[11] = 0, 0 // IPv4 checksum offload.
	packet[26], packet[27] = 0, 0 // UDP checksum offload.
	ip, err := prepareIPv4(packet, testClientIP())
	if err != nil {
		t.Fatal(err)
	}
	if ip[8] != 63 || netip.AddrFrom4([4]byte(ip[12:16])).String() != "198.18.77.2" ||
		binary.BigEndian.Uint16(ip[20:22]) != 12345 || ether.Checksum(ip[:20]) != 0 {
		t.Fatalf("address, TTL or header checksum changed incorrectly: %x", ip)
	}
	u := ip[20:]
	if ether.Checksum(ip[12:16], ip[16:20], []byte{0, 17, 0, byte(len(u))}, u) != 0 {
		t.Fatal("invalid repaired UDP checksum")
	}
	if packet[8] != 64 {
		t.Fatal("input capture buffer was mutated")
	}
}

func TestPacketRejectsOutOfScopeAndUnimplementedCases(t *testing.T) {
	for _, v := range []struct {
		name string
		edit func([]byte)
	}{
		{"expired", func(p []byte) { p[8] = 1 }},
		{"fragment", func(p []byte) { p[6] = 0x20 }},
		{"other client", func(p []byte) { p[15] = 3 }},
		{"invalid UDP length", func(p []byte) { p[25] = 7 }},
		{"other family", func(p []byte) { p[0] = 0x65 }},
	} {
		t.Run(v.name, func(t *testing.T) {
			p := testPacket(t)
			v.edit(p)
			if _, err := prepareIPv4(p, testClientIP()); err == nil {
				t.Fatal("packet accepted")
			}
		})
	}
}

func TestExplicitClientScope(t *testing.T) {
	client := netip.MustParseAddr("192.0.2.50")
	p := testUDPPacket(t, client, []byte("probe"))
	ip, err := prepareIPv4(p, client)
	if err != nil || !bytes.Equal(ip[12:16], client.AsSlice()) {
		t.Fatalf("explicit scope: %v", err)
	}
	if _, err := prepareIPv4(p, testClientIP()); err == nil {
		t.Fatal("packet from another client accepted")
	}
}

func TestLiveLANScope(t *testing.T) {
	name := os.Getenv("LANTERN_TEST_LAN_IFACE")
	if name == "" {
		t.Skip("requires an explicitly selected LAN and controlled client; reads settings only")
	}
	lan, err := network.InspectWindowsInterface(name)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := netip.ParseAddr(os.Getenv("LANTERN_TEST_CLIENT_IP"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateClient(lan, ip); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "127.0.0.1", "224.0.0.1", "255.255.255.255", "2001:db8::1"} {
		address, _ := netip.ParseAddr(invalid)
		if err := validateClient(lan, address); err == nil {
			t.Fatalf("accepted invalid client %q", invalid)
		}
	}
	lan.GUID = "{00000000-0000-0000-0000-000000000000}"
	if err := verifyLAN(lan, ip); err == nil {
		t.Fatal("changed LAN instance accepted")
	}
}
