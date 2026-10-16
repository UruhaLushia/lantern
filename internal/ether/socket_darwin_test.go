package ether

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"slices"
	"testing"
	"time"
)

func record(header int, data []byte, original int) []byte {
	b := make([]byte, (header+len(data)+3)&^3)
	binary.NativeEndian.PutUint32(b[8:], uint32(len(data)))
	binary.NativeEndian.PutUint32(b[12:], uint32(original))
	binary.NativeEndian.PutUint16(b[16:], uint16(header))
	copy(b[header:], data)
	return b
}

func TestBPFRecordAlignmentAndTruncation(t *testing.T) {
	first, second := []byte{1, 2, 3, 4, 5}, []byte{6, 7, 8}
	pending := append(record(18, first, len(first)), record(22, []byte{0xff}, 100)...)
	pending = append(pending, record(22, second, len(second))...)
	c := &bpfSocket{fd: 0, pending: pending, readUntil: time.Now().Add(time.Second)}
	for _, want := range [][]byte{first, second} {
		b := make([]byte, 64)
		n, _, err := c.ReadFrom(b)
		if err != nil || !slices.Equal(b[:n], want) {
			t.Fatalf("read %x, %v; want %x", b[:n], err, want)
		}
	}
	if len(c.pending) != 0 {
		t.Fatalf("unconsumed records: %x", c.pending)
	}
}

func TestBPFRejectsMalformedRecords(t *testing.T) {
	valid := record(18, []byte{1}, 1)
	badHeader := slices.Clone(valid)
	binary.NativeEndian.PutUint16(badHeader[16:], 17)
	badCapture := slices.Clone(valid)
	binary.NativeEndian.PutUint32(badCapture[8:], 0xffffffff)
	for _, b := range [][]byte{{1, 2}, badHeader, badCapture} {
		c := &bpfSocket{fd: 0, pending: b}
		if _, _, err := c.ReadFrom(make([]byte, 64)); err == nil {
			t.Fatalf("accepted malformed BPF record %x", b)
		}
	}
}

func TestBPFDeadlineAndClosed(t *testing.T) {
	for _, tc := range []struct {
		fd       int
		deadline time.Time
		want     error
	}{{-1, time.Time{}, net.ErrClosed}, {0, time.Now().Add(-time.Second), os.ErrDeadlineExceeded}} {
		c := &bpfSocket{fd: tc.fd, readUntil: tc.deadline}
		if _, _, err := c.ReadFrom(nil); !errors.Is(err, tc.want) {
			t.Fatalf("got %v, want %v", err, tc.want)
		}
	}
}
