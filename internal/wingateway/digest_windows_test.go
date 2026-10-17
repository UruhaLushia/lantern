package wingateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestPacketDigestCanonicalBytes(t *testing.T) {
	udp := append([]byte(nil), testPacket(t)...)
	tcp := append([]byte(nil), udp[:20]...)
	tcp = append(tcp, make([]byte, 25)...)
	tcp[9], tcp[32] = 6, 0x50
	binary.BigEndian.PutUint16(tcp[2:4], uint16(len(tcp)))
	tcp[36], tcp[37] = 0xab, 0xcd
	options := append([]byte(nil), tcp[:20]...)
	options[0] = 0x46
	options = append(options, 1, 1, 1, 1)
	options = append(options, tcp[20:]...)
	binary.BigEndian.PutUint16(options[2:4], uint16(len(options)))
	for _, packet := range [][]byte{udp, tcp, options} {
		original := append([]byte(nil), packet...)
		canonical := append([]byte(nil), packet...)
		canonical[10], canonical[11] = 0, 0
		offset := int(canonical[0]&15)*4 + 6
		if canonical[9] == 6 {
			offset += 10
		}
		canonical[offset], canonical[offset+1] = 0, 0
		want := sha256.Sum256(canonical)
		if got := packetDigest(packet); got != want || !bytes.Equal(packet, original) {
			t.Fatal("fingerprint differs from canonical packet or changed its input")
		}
		if got := packetDigest(append(append([]byte(nil), packet...), 1, 2, 3)); got != want {
			t.Fatal("capture padding affected fingerprint")
		}
		packet[8]--
		if packetDigest(packet) == want {
			t.Fatal("TTL change omitted from fingerprint")
		}
	}
	for n := 0; n < len(tcp); n++ {
		packetDigest(tcp[:n]) // Malformed captures must not panic.
	}
}

func TestPreparedPacketBufferOwnership(t *testing.T) {
	packet := append([]byte(nil), testPacket(t)...)
	original := append([]byte(nil), packet...)
	storage := make([]byte, 0, 65535)
	prepared, err := prepareIPv4Into(storage, packet, testClientIP())
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), prepared...)
	if &prepared[0] != &storage[:cap(storage)][0] || !bytes.Equal(original, packet) {
		t.Fatal("did not reuse output storage or modified capture")
	}
	for range 3 {
		prepared, err = prepareIPv4Into(prepared[:0], packet, testClientIP())
		if err != nil || !bytes.Equal(prepared, want) || !bytes.Equal(packet, original) {
			t.Fatal("buffer reuse changed TTL, checksum or capture")
		}
	}
	// The next receive may overwrite its buffer, but never the prepared send.
	clear(packet)
	if !bytes.Equal(prepared, want) {
		t.Fatal("send buffer aliases receive buffer")
	}
}
