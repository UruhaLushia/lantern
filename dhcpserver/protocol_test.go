package dhcpserver

import (
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/UruhaLushia/lantern/device"
	"github.com/UruhaLushia/lantern/discovery"
	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/UruhaLushia/lantern/network"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

type protocolLink struct {
	mu      sync.Mutex
	handler func(discovery.DHCPEvent)
	frames  [][]byte
}

func (p *protocolLink) SetDHCPHandler(h func(discovery.DHCPEvent)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handler = h
}

func (p *protocolLink) Send(frame []byte, _ net.HardwareAddr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.frames = append(p.frames, slices.Clone(frame))
	return nil
}

func (p *protocolLink) replies(t *testing.T) []*dhcpv4.DHCPv4 {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	var result []*dhcpv4.DHCPv4
	for _, b := range p.frames {
		f, err := ether.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		if f.EtherType == 0x806 {
			continue // ARP conflict probe: no real link transmission.
		}
		d, err := ether.IP(f)
		if err != nil {
			t.Fatal(err)
		}
		d, err = ether.UDP(d)
		if err != nil || d.SourcePort != 67 || d.DestinationPort != 68 {
			t.Fatalf("invalid DHCP reply transport: %+v, %v", d, err)
		}
		packet, err := dhcpv4.FromBytes(d.Payload)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, packet)
	}
	return result
}

func startProtocolService(t *testing.T, path string, configure func(*Options)) (*Service, *protocolLink) {
	t.Helper()
	selected := network.Selection{Interface: network.Interface{Name: "isolated-test", MAC: "02:00:00:00:00:01", Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.77.1/24")}}, GatewayIPv4: netip.MustParseAddr("198.18.77.2")}
	opts := Options{Enabled: true, ExclusivePool: true, PoolStart: netip.MustParseAddr("198.18.77.5"), PoolEnd: netip.MustParseAddr("198.18.77.8"), DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, LeaseFile: path}
	if configure != nil {
		configure(&opts)
	}
	link := &protocolLink{}
	// The lifecycle drains a loopback ephemeral socket; all protocol output is
	// captured above. No UDP 67/68 binding, broadcast, or real NIC is involved.
	s, err := start(t.Context(), selected, opts, link, device.NewStore(32), func() error { return nil }, func(string, netip.Addr) (net.PacketConn, error) {
		return net.ListenPacket("udp4", "127.0.0.1:0")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	s.mu.Lock()
	s.status.ObservingUntil = time.Time{}
	s.mu.Unlock()
	return s, link
}

func protocolDiscovery(t *testing.T) *dhcpv4.DHCPv4 {
	t.Helper()
	p, err := dhcpv4.NewDiscovery(net.HardwareAddr{2, 0, 0, 0, 0, 2}, dhcpv4.WithOption(dhcpv4.OptHostName("android-test")))
	if err != nil {
		t.Fatal(err)
	}
	p.SetBroadcast()
	return p
}

func protocolEvent(p *dhcpv4.DHCPv4) discovery.DHCPEvent {
	return discovery.DHCPEvent{Packet: p, SourceIP: netip.IPv4Unspecified(), SourceMAC: slices.Clone(p.ClientHWAddr)}
}

func TestProtocolDORATakeoverRenewReleaseAndRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	s, link := startProtocolService(t, path, nil)
	discover := protocolDiscovery(t)
	s.process(t.Context(), protocolEvent(discover), 24)
	replies := link.replies(t)
	if len(replies) != 1 || replies[0].MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("missing OFFER: %+v; %+v", replies, s.Snapshot())
	}
	offer := replies[0]
	request, err := dhcpv4.NewRequestFromOffer(offer, dhcpv4.WithOption(dhcpv4.OptHostName("android-test")))
	if err != nil {
		t.Fatal(err)
	}
	for i, takeover := range []bool{false, true, false} {
		var macs []string
		want := s.opts.Gateway
		if takeover {
			macs, want = []string{request.ClientHWAddr.String()}, s.opts.ServerIP
		}
		if err := s.SetGatewayMACs(macs); err != nil {
			t.Fatal(err)
		}
		s.process(t.Context(), protocolEvent(request), 24)
		replies = link.replies(t)
		if len(replies) != i+2 {
			t.Fatalf("ACK missing: %+v", s.Snapshot())
		}
		ack := replies[len(replies)-1]
		if ack.MessageType() != dhcpv4.MessageTypeAck || len(ack.Router()) != 1 || !ack.Router()[0].Equal(want.AsSlice()) || !ack.YourIPAddr.Equal(s.opts.PoolStart.AsSlice()) || len(ack.DNS()) != 1 || ack.IPAddressLeaseTime(0) != s.opts.Lease {
			t.Fatalf("unexpected ACK: %s", ack.Summary())
		}
	}
	if len(s.store.Snapshot()) != 1 || s.Snapshot().Leases[0].Hostname != "android-test" {
		t.Fatal("ACK did not update device metadata")
	}
	request.ClientIPAddr = s.opts.PoolStart.AsSlice()
	s.process(t.Context(), protocolEvent(request), 24)
	renewals := link.replies(t)
	if ack := renewals[len(renewals)-1]; !ack.ClientIPAddr.Equal(request.ClientIPAddr) {
		t.Fatal("renewal ACK lost ciaddr")
	}
	// A new service must restore the bound lease and its device ownership.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restored, _ := startProtocolService(t, path, nil)
	if leases := restored.Snapshot().Leases; len(leases) != 1 || leases[0].State != "bound" || leases[0].IP != s.opts.PoolStart || len(restored.store.Snapshot()) != 1 {
		t.Fatalf("bound lease recovery: %+v", leases)
	}
	release, err := dhcpv4.New(dhcpv4.WithHwAddr(request.ClientHWAddr), dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease), dhcpv4.WithClientIP(s.opts.PoolStart.AsSlice()))
	if err != nil {
		t.Fatal(err)
	}
	restored.process(t.Context(), protocolEvent(release), 24)
	if restored.Snapshot().Leases[0].ExpiresAt.After(time.Now()) {
		t.Fatal("release retained an active lease")
	}
}

func TestProtocolDoesNotACKUntilForwardingPrepared(t *testing.T) {
	reject := true
	prepared := false
	s, link := startProtocolService(t, filepath.Join(t.TempDir(), "leases.json"), func(o *Options) {
		o.GatewayMACs = []string{"02:00:00:00:00:02"}
		o.OnLease = func(l Lease, selected bool) error {
			if reject && l.State == "bound" {
				return errors.New("forwarding preparation failed")
			}
			prepared = selected && l.State == "bound" && l.ExpiresAt.After(time.Now())
			return nil
		}
	})
	discover := protocolDiscovery(t)
	s.process(t.Context(), protocolEvent(discover), 24)
	replies := link.replies(t)
	if len(replies) != 1 {
		t.Fatal("missing OFFER")
	}
	request, err := dhcpv4.NewRequestFromOffer(replies[0])
	if err != nil {
		t.Fatal(err)
	}
	s.process(t.Context(), protocolEvent(request), 24)
	if prepared || len(link.replies(t)) != 1 || s.Snapshot().LastError != "forwarding preparation failed" {
		t.Fatal("ACK preceded forwarding authorization")
	}
	reject = false
	s.process(t.Context(), protocolEvent(request), 24)
	if !prepared || len(link.replies(t)) != 2 {
		t.Fatal("prepared binding was not acknowledged")
	}
	if err := s.SetGatewayMACs(nil); err != nil || prepared {
		t.Fatalf("gateway removal retained authorization: %v", err)
	}
}

func TestProtocolRejectsSpoofRelayAndForeignSelection(t *testing.T) {
	s, link := startProtocolService(t, filepath.Join(t.TempDir(), "leases.json"), nil)
	for _, edit := range []func(*discovery.DHCPEvent){
		func(e *discovery.DHCPEvent) { e.SourceMAC = net.HardwareAddr{2, 0, 0, 0, 0, 3} },
		func(e *discovery.DHCPEvent) { e.Tagged = true },
		func(e *discovery.DHCPEvent) { e.Packet.HopCount = 1 },
		func(e *discovery.DHCPEvent) { e.Packet.GatewayIPAddr = net.ParseIP("198.18.77.3") },
		func(e *discovery.DHCPEvent) {
			e.Packet.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("198.18.77.3")))
		},
	} {
		e := protocolEvent(protocolDiscovery(t))
		edit(&e)
		s.process(t.Context(), e, 24)
	}
	if len(link.replies(t)) != 0 || len(s.Snapshot().Leases) != 0 {
		t.Fatal("rejected request allocated a lease or replied")
	}
	s.ready = func() error { return errors.New("datapath unavailable") }
	s.process(t.Context(), protocolEvent(protocolDiscovery(t)), 24)
	if len(link.replies(t)) != 0 || s.Snapshot().LastError != "datapath unavailable" {
		t.Fatal("DHCP replied with an unavailable gateway")
	}
}

func TestProtocolConflictPausesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	s, link := startProtocolService(t, path, nil)
	p, err := dhcpv4.NewReplyFromRequest(protocolDiscovery(t), dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer), dhcpv4.WithYourIP(s.opts.PoolStart.AsSlice()), dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP("198.18.77.3"))))
	if err != nil {
		t.Fatal(err)
	}
	s.Handle(protocolEvent(p))
	s.process(t.Context(), protocolEvent(protocolDiscovery(t)), 24)
	if s.Snapshot().Conflicts != 1 || s.Snapshot().PausedReason == "" || len(link.replies(t)) != 0 {
		t.Fatal("overlapping server failed to pause allocations")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restored, _ := startProtocolService(t, path, nil)
	if restored.Snapshot().PausedReason == "" {
		t.Fatal("restart lost conflict pause")
	}
	if err := restored.Resume(); err != nil || restored.Snapshot().PausedReason != "" || !restored.Snapshot().ObservingUntil.After(time.Now()) {
		t.Fatalf("resume did not reobserve upstream: %v", err)
	}
}
