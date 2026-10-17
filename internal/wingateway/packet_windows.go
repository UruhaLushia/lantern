package wingateway

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/UruhaLushia/lantern/internal/ether"
)

var errTTL = errors.New("IPv4 TTL expired")

// prepareIPv4Into reuses dst's capacity but never modifies the capture buffer.
// dst must not overlap p. The caller owns the output until sending completes.
func prepareIPv4Into(dst, p []byte, client netip.Addr) ([]byte, error) {
	if len(p) < 20 {
		return nil, errors.New("short IPv4 packet")
	}
	h, n := int(p[0]&15)*4, int(binary.BigEndian.Uint16(p[2:4]))
	fragment := binary.BigEndian.Uint16(p[6:8])
	if p[0]>>4 != 4 || h < 20 || n < h || n > len(p) || fragment&0x8000 != 0 || (fragment&0x4000 != 0 && fragment&0x3fff != 0) ||
		netip.AddrFrom4([4]byte(p[12:16])) != client {
		return nil, errors.New("invalid IPv4 packet")
	}
	if p[8] <= 1 {
		return nil, errTTL
	}
	destination := netip.AddrFrom4([4]byte(p[16:20]))
	if !destination.IsGlobalUnicast() {
		return nil, errors.New("destination must be unicast")
	}
	if h > 20 {
		var options [40]byte
		if _, err := copiedOptions(p[:h], options[:0]); err != nil {
			return nil, err
		}
	}
	p = append(dst[:0], p[:n]...)
	p[8]--
	p[10], p[11] = 0, 0
	binary.BigEndian.PutUint16(p[10:12], ether.Checksum(p[:h]))
	if fragment&0x3fff != 0 {
		if n == h || (fragment&0x2000 != 0 && (n-h)%8 != 0) || int(fragment&0x1fff)*8+n-h > 65535-h {
			return nil, errors.New("invalid IPv4 fragment")
		}
		return p, nil // Routers preserve fragment payload and its transport checksum.
	}
	// Capture offload metadata is not carried into injection. Recompute the
	// TCP/UDP checksum over the complete unfragmented packet explicitly.
	u := p[h:]
	var offset int
	switch p[9] {
	case 6:
		if len(u) < 20 || int(u[12]>>4)*4 < 20 || int(u[12]>>4)*4 > len(u) {
			return nil, errors.New("invalid TCP")
		}
		offset = 16
	case 17:
		if len(u) < 8 || int(binary.BigEndian.Uint16(u[4:6])) != len(u) {
			return nil, errors.New("invalid UDP")
		}
		offset = 6
	case 1:
		if len(u) < 8 {
			return nil, errors.New("invalid ICMP")
		}
		u[2], u[3] = 0, 0
		binary.BigEndian.PutUint16(u[2:4], ether.Checksum(u))
		return p, nil
	default:
		return p, nil // Other IPv4 protocols have no shared transport checksum.
	}
	u[offset], u[offset+1] = 0, 0
	pseudo := []byte{0, p[9], byte(len(u) >> 8), byte(len(u))}
	checksum := ether.Checksum(p[12:16], p[16:20], pseudo, u)
	if checksum == 0 && p[9] == 17 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(u[offset:offset+2], checksum)
	return p, nil
}
