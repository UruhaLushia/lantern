package wingateway

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/UruhaLushia/lantern/internal/ether"
)

// prepareForEgress also implements TTL expiry and PMTU feedback. Oversized
// datagrams are reported instead of submitting a packet larger than the TUN's
// current MTU with DF set. Non-DF datagrams proceed to the fragmenter.
func prepareForEgress(dst, p []byte, client, local netip.Addr, mtu uint32) ([]byte, error) {
	prepared, err := prepareIPv4Into(dst, p, client)
	if errors.Is(err, errTTL) {
		return icmpError(dst, p, local, 11, 0, 0)
	}
	if err != nil {
		return nil, err
	}
	if mtu >= 68 && uint32(len(prepared)) > mtu && binary.BigEndian.Uint16(prepared[6:8])&0x4000 != 0 {
		return icmpError(dst, p, local, 3, 4, uint16(min(mtu, 65535)))
	}
	return prepared, nil
}

func icmpError(dst, original []byte, local netip.Addr, kind, code byte, mtu uint16) ([]byte, error) {
	if len(original) < 20 {
		return nil, errors.New("short ICMP error quote")
	}
	h := int(original[0]&15) * 4
	n := int(binary.BigEndian.Uint16(original[2:4]))
	if h < 20 || n < h || n > len(original) || !netip.AddrFrom4([4]byte(original[16:20])).IsGlobalUnicast() || binary.BigEndian.Uint16(original[6:8])&0x1fff != 0 ||
		(original[9] == 1 && n > h && original[h] != 0 && original[h] != 8 && original[h] != 13 && original[h] != 14 && original[h] != 15 && original[h] != 16) {
		return nil, errors.New("ICMP error response suppressed")
	}
	quote := original[:min(n, h+8)]
	p := append(dst[:0], make([]byte, 28+len(quote))...)
	p[0], p[8], p[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], local.AsSlice())
	copy(p[16:20], original[12:16])
	binary.BigEndian.PutUint16(p[10:12], ether.Checksum(p[:20]))
	p[20], p[21] = kind, code
	binary.BigEndian.PutUint16(p[26:28], mtu)
	copy(p[28:], quote)
	binary.BigEndian.PutUint16(p[22:24], ether.Checksum(p[20:]))
	return p, nil
}
