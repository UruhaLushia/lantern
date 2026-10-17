package dhcpserver

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

type replyRecorder struct {
	net.PacketConn
	payload     []byte
	destination *net.UDPAddr
}

func (r *replyRecorder) WriteTo(p []byte, dst net.Addr) (int, error) {
	r.payload = slices.Clone(p)
	r.destination = dst.(*net.UDPAddr)
	return len(p), nil
}

func TestNativeDHCPBroadcastAndRenewUnicast(t *testing.T) {
	for _, ciaddr := range []net.IP{net.IPv4zero, net.ParseIP("198.18.77.5")} {
		request := protocolDiscovery(t)
		request.ClientIPAddr = ciaddr
		ack, err := dhcpv4.NewReplyFromRequest(request, dhcpv4.WithMessageType(dhcpv4.MessageTypeAck), dhcpv4.WithClientIP(ciaddr))
		if err != nil {
			t.Fatal(err)
		}
		mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
		frame, err := ether.IPv4UDP(mac, mac, netip.MustParseAddr("198.18.77.1"), netip.MustParseAddr("198.18.77.5"), 67, 68, ack.ToBytes())
		if err != nil {
			t.Fatal(err)
		}
		recorder := &replyRecorder{}
		if err := sendReplyFrame(&Service{socket: recorder}, frame, mac); err != nil {
			t.Fatal(err)
		}
		want := ciaddr
		if ciaddr.IsUnspecified() {
			want = net.IPv4bcast
		}
		if recorder.destination.Port != 68 || !recorder.destination.IP.Equal(want) {
			t.Fatalf("DHCP reply destination: %+v", recorder.destination)
		}
		p, err := dhcpv4.FromBytes(recorder.payload)
		if err != nil || p.TransactionID != request.TransactionID {
			t.Fatalf("DHCP reply payload: %v", err)
		}
	}
}
