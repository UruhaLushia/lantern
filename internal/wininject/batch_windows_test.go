package wininject

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

func batchPacket(size int, fill byte) []byte {
	p := bytes.Repeat([]byte{fill}, size)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	return p
}

func TestBatchPackingBoundariesAndOwnership(t *testing.T) {
	packets := [][]byte{batchPacket(20, 1), batchPacket(29, 2), batchPacket(1500, 3)}
	want := bytes.Join(packets, nil)
	storage := make([]byte, 0, 4096)
	packed, err := packBatch(storage, packets)
	if err != nil || !bytes.Equal(packed, want) || &packed[0] != &storage[:1][0] {
		t.Fatalf("incorrect contiguous packing or storage reuse: %v", err)
	}
	for offset, i := 0, 0; i < len(packets); i++ {
		size := int(binary.BigEndian.Uint16(packed[offset+2 : offset+4]))
		if size != len(packets[i]) || !bytes.Equal(packed[offset:offset+size], packets[i]) {
			t.Fatal("driver-visible boundary differs from packet boundary")
		}
		offset += size
	}
	clear(packed)
	if !bytes.Equal(bytes.Join(packets, nil), want) {
		t.Fatal("packed storage aliases caller-owned packets")
	}
	maximum := make([][]byte, maxBatchPackets)
	for i := range maximum {
		maximum[i] = batchPacket(65535, 0xff)
	}
	if size, err := batchSize(maximum); err != nil || size != maxBatchPackets*65535 {
		t.Fatalf("maximum bounded batch: %d, %v", size, err)
	}
}

func TestBatchRejectsMalformedBeforeSubmission(t *testing.T) {
	for _, change := range []func([]byte) []byte{
		func(p []byte) []byte { return p[:19] },
		func(p []byte) []byte { p[0] = 0x65; return p },
		func(p []byte) []byte { p[0] = 0x44; return p },
		func(p []byte) []byte { p[0] = 0x4f; return p },
		func(p []byte) []byte { p[3]--; return p },
		func(p []byte) []byte { return append(p, 1) },
	} {
		if _, err := packBatch(nil, [][]byte{batchPacket(20, 1), change(batchPacket(28, 2))}); err == nil {
			t.Fatal("accepted an invalid packet inside the batch")
		}
	}
	if _, err := packBatch(nil, nil); err == nil {
		t.Fatal("accepted empty batch")
	}
	if _, err := packBatch(nil, make([][]byte, maxBatchPackets+1)); err == nil {
		t.Fatal("accepted excessive packet count")
	}
	var sender Sender
	if err := sender.SendBatch([][]byte{batchPacket(20, 0)}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed sender: %v", err)
	}
}
