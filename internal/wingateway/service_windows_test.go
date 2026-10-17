package wingateway

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/UruhaLushia/lantern/internal/ether"
)

func TestArbitraryIPv4TargetsAndPorts(t *testing.T) {
	p := testPacket(t)
	copy(p[16:20], netip.MustParseAddr("9.9.9.9").AsSlice())
	binary.BigEndian.PutUint16(p[22:24], 53)
	out, err := prepareIPv4(p, testClientIP())
	if err != nil || !bytes.Equal(out[12:24], p[12:24]) || out[8] != p[8]-1 {
		t.Fatalf("arbitrary DNS destination/port: %v", err)
	}
}

func TestIPv4FragmentPreservesPayloadAndRepairsHeader(t *testing.T) {
	p := testUDPPacket(t, testClientIP(), make([]byte, 16))
	binary.BigEndian.PutUint16(p[6:8], 0x2000)
	out, err := prepareIPv4(p, testClientIP())
	if err != nil || !bytes.Equal(out[20:], p[20:]) || ether.Checksum(out[:20]) != 0 {
		t.Fatalf("first fragment changed transport checksum/payload: %v", err)
	}
	binary.BigEndian.PutUint16(p[6:8], 3) // A final, non-first fragment.
	out, err = prepareIPv4(p, testClientIP())
	if err != nil || !bytes.Equal(out[20:], p[20:]) {
		t.Fatalf("non-first fragment: %v", err)
	}
	before := packetDigest(p)
	p[26] ^= 1
	if before == packetDigest(p) {
		t.Fatal("fragment payload was mistaken for an offloaded UDP checksum")
	}
}

func TestTTLAndMTUReturnICMPToClient(t *testing.T) {
	local := netip.MustParseAddr("198.18.77.1")
	for _, tc := range []struct {
		ttl        byte
		size       int
		mtu        uint32
		kind, code byte
	}{
		{1, 100, 1500, 11, 0}, {64, 1500, 1280, 3, 4},
	} {
		p := testUDPPacket(t, testClientIP(), make([]byte, tc.size-28))
		p[8], p[6] = tc.ttl, 0x40 // DF.
		out, err := prepareForEgress(make([]byte, 0, 65535), p, testClientIP(), local, tc.mtu)
		if err != nil {
			t.Fatal(err)
		}
		if netip.AddrFrom4([4]byte(out[12:16])) != local || netip.AddrFrom4([4]byte(out[16:20])) != testClientIP() || out[20] != tc.kind || out[21] != tc.code || ether.Checksum(out[:20]) != 0 || ether.Checksum(out[20:]) != 0 || !bytes.Equal(out[28:], p[:28]) {
			t.Fatalf("invalid ICMP error: %x", out)
		}
		if tc.code == 4 && binary.BigEndian.Uint16(out[26:28]) != uint16(tc.mtu) {
			t.Fatal("missing next-hop MTU")
		}
	}
}

func TestRecentPacketsBoundedAndKeepsRetransmissions(t *testing.T) {
	original := testPacket(t)
	prepared, err := prepareIPv4(original, testClientIP())
	if err != nil {
		t.Fatal(err)
	}
	r := newRecentPackets()
	r.add(prepared)
	prepared[10], prepared[11], prepared[26], prepared[27] = 0, 0, 0, 0
	if !r.contains(prepared) || r.contains(original) {
		t.Fatal("self copy or original client retransmission misclassified")
	}
	for i := 0; i < 70000; i++ {
		binary.BigEndian.PutUint32(prepared[12:16], uint32(i))
		r.add(prepared)
	}
	if len(r.seen) > len(r.ring) {
		t.Fatal("recapture history grows with gateway uptime")
	}
}

func TestBindingSourcesPreserveManualAndExpire(t *testing.T) {
	manual, leased := netip.MustParseAddr("198.18.77.2"), netip.MustParseAddr("198.18.77.3")
	s := &Service{manual: sourceSet{manual: time.Time{}}, bindings: map[string]binding{"client": {leased, time.Now().Add(time.Hour)}}}
	s.publishSourcesLocked()
	if len(*s.sources.Load()) != 2 {
		t.Fatal("lease replaced manual scope")
	}
	s.bindings["client"] = binding{leased, time.Now().Add(-time.Second)}
	s.publishSourcesLocked()
	if len(*s.sources.Load()) != 1 || len(s.bindings) != 0 {
		t.Fatal("expired binding retained forwarding authorization")
	}
	s.bindings["other"] = binding{leased, time.Now().Add(time.Hour)}
	s.ClearLeases()
	if len(s.bindings) != 0 || len(*s.sources.Load()) != 1 {
		t.Fatal("DHCP shutdown retained a binding or cleared manual clients")
	}
}

func TestIPv4FragmentationRoundTripAndDF(t *testing.T) {
	original := testUDPPacket(t, testClientIP(), make([]byte, 1400))
	original = append(original, make([]byte, 1600)...)
	binary.BigEndian.PutUint16(original[2:4], uint16(len(original)))
	binary.BigEndian.PutUint16(original[24:26], uint16(len(original)-20))
	for i := 28; i < len(original); i++ {
		original[i] = byte(i)
	}
	p, err := prepareForEgress(nil, original, testClientIP(), netip.MustParseAddr("198.18.77.1"), 1280)
	if err != nil {
		t.Fatal(err)
	}
	var reassembled []byte
	scratch := make([]byte, 0, 65535)
	for offset := 0; offset < len(p)-20; {
		fragment, next, err := fragmentIPv4Into(scratch, p, offset, 1280)
		if err != nil {
			t.Fatal(err)
		}
		flags := binary.BigEndian.Uint16(fragment[6:8])
		if len(fragment) > 1280 || int(flags&0x1fff)*8 != offset || ether.Checksum(fragment[:20]) != 0 || (flags&0x2000 != 0) != (next < len(p)-20) {
			t.Fatalf("invalid fragmentation: offset=%d, next=%d, flags=%x", offset, next, flags)
		}
		reassembled = append(reassembled, fragment[20:]...)
		scratch = fragment[:0]
		offset = next
	}
	if !bytes.Equal(reassembled, p[20:]) {
		t.Fatal("fragment reassembly changed the transport payload")
	}
	p[6] |= 0x40
	if _, _, err := fragmentIPv4Into(nil, p, 0, 1280); err == nil {
		t.Fatal("DF datagram was fragmented")
	}
}

func TestIPv4CopiedOptionsAndSourceRouteRejection(t *testing.T) {
	options, err := copiedOptions(append(make([]byte, 20), 1, 0x82, 4, 1, 2, 0x44, 3, 0, 0, 0, 0, 0), nil)
	if err != nil || !bytes.Equal(options, []byte{0x82, 4, 1, 2}) {
		t.Fatalf("fragment copy options: %x, %v", options, err)
	}
	for _, option := range [][]byte{{131, 4, 0, 0}, {137, 4, 0, 0}, {0x82, 1, 0, 0}, {0x82, 8, 0, 0}} {
		if _, err := copiedOptions(append(make([]byte, 20), option...), nil); err == nil {
			t.Fatalf("invalid routing option accepted: %x", option)
		}
	}
}

func TestRecentFingerprintExpires(t *testing.T) {
	r := newRecentPackets()
	p := testPacket(t)
	r.add(p)
	key := packetDigest(p)
	stamp := r.seen[key]
	stamp.tick -= int64(3 * time.Second)
	r.seen[key] = stamp
	if r.contains(p) {
		t.Fatal("stale recapture fingerprint suppressed a later real packet")
	}
}

func TestObserverDetachWaitsForBorrowedBuffer(t *testing.T) {
	s := &Service{}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s.SetPacketObserver(func([]byte) { close(entered); <-release })
	go s.observe([]byte{1})
	<-entered
	go func() { s.SetPacketObserver(nil); close(done) }()
	select {
	case <-done:
		t.Fatal("observer detached before its borrowed buffer was released")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("observer detach blocked after callback completed")
	}
	s.observe([]byte{2}) // A detached observer must never run again.
}
