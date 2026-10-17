package ether

import (
	"bytes"
	"fmt"
	"testing"
)

// Fold after every word as an independent, deliberately simple reference.
func referenceChecksum(p []byte) uint16 {
	var sum uint32
	for len(p) >= 2 {
		sum += uint32(p[0])<<8 | uint32(p[1])
		sum = (sum & 0xffff) + (sum >> 16)
		p = p[2:]
	}
	if len(p) != 0 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func TestChecksumPartBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, 2, 3, 7, 8, 9, 63, 512, 1500, 65535, 262144} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			p := make([]byte, size)
			for i := range p {
				p[i] = byte(i*37 + i/7)
			}
			for _, data := range [][]byte{p, bytes.Repeat([]byte{0xff}, size)} {
				want := referenceChecksum(data)
				if got := Checksum(data); got != want {
					t.Fatalf("checksum=%04x, want %04x", got, want)
				}
				for _, width := range []int{1, 2, 3, 7, 8, 9, 31, 512} {
					parts := [][]byte{nil}
					for start := 0; start < len(data); start += width {
						parts = append(parts, data[start:min(start+width, len(data))], nil)
					}
					if got := Checksum(parts...); got != want {
						t.Fatalf("part width %d: checksum=%04x, want %04x", width, got, want)
					}
				}
			}
		})
	}
}
