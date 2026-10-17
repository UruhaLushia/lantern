package wingateway

import (
	"encoding/binary"
	"errors"

	"github.com/UruhaLushia/lantern/internal/ether"
)

// copiedOptions validates the option list and retains only options marked for
// copying into later fragments. Source-route options cannot bypass our explicit
// egress-route check and are therefore rejected.
func copiedOptions(header []byte, dst []byte) ([]byte, error) {
	dst = dst[:0]
	for p := header[20:]; len(p) > 0; {
		kind := p[0]
		if kind == 0 {
			break
		}
		if kind == 1 {
			p = p[1:]
			continue
		}
		if len(p) < 2 || p[1] < 2 || int(p[1]) > len(p) || kind == 131 || kind == 137 {
			return nil, errors.New("malformed or source-route IPv4 option")
		}
		n := int(p[1])
		if kind&0x80 != 0 {
			dst = append(dst, p[:n]...)
		}
		p = p[n:]
	}
	for len(dst)%4 != 0 {
		dst = append(dst, 0)
	}
	return dst, nil
}

// fragmentIPv4Into consumes payload starting at offset, preserving an existing
// fragment's base offset/MF bit. The caller waits for synchronous submission
// before reusing dst; packet must not alias dst.
func fragmentIPv4Into(dst, packet []byte, offset, mtu int) ([]byte, int, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 || mtu < 68 {
		return nil, 0, errors.New("invalid fragmentation input")
	}
	h := int(packet[0]&15) * 4
	if h < 20 || h > len(packet) || offset < 0 || offset%8 != 0 || offset >= len(packet)-h || binary.BigEndian.Uint16(packet[6:8])&0x4000 != 0 {
		return nil, 0, errors.New("invalid IPv4 fragment boundary")
	}
	var optionSpace [40]byte
	options, err := copiedOptions(packet[:h], optionSpace[:0])
	if err != nil {
		return nil, 0, err
	}
	base := binary.BigEndian.Uint16(packet[6:8])
	newHeader := 20 + len(options)
	if offset == 0 && base&0x1fff == 0 {
		newHeader = h
		options = packet[20:h]
	}
	size := min(len(packet)-h-offset, mtu-newHeader)
	if offset+size < len(packet)-h {
		size = size / 8 * 8
	}
	if size <= 0 || int(base&0x1fff)+offset/8 > 0x1fff {
		return nil, 0, errors.New("IPv4 MTU cannot fit a fragment")
	}
	p := append(dst[:0], packet[:20]...)
	p = append(p, options...)
	p = append(p, packet[h+offset:h+offset+size]...)
	p[0] = 0x40 | byte(newHeader/4)
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	flags := base&0x2000 | uint16(int(base&0x1fff)+offset/8)
	if offset+size < len(packet)-h {
		flags |= 0x2000
	}
	binary.BigEndian.PutUint16(p[6:8], flags)
	p[10], p[11] = 0, 0
	binary.BigEndian.PutUint16(p[10:12], ether.Checksum(p[:newHeader]))
	return p, offset + size, nil
}
