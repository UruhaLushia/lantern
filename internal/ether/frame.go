package ether

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

type Frame struct {
	SourceMAC, DestinationMAC net.HardwareAddr
	EtherType                 uint16
	Payload                   []byte
	Tagged                    bool
}

func Parse(b []byte) (Frame, error) {
	if len(b) < 14 {
		return Frame{}, errors.New("short Ethernet header")
	}
	f := Frame{DestinationMAC: b[:6], SourceMAC: b[6:12], EtherType: binary.BigEndian.Uint16(b[12:14]), Payload: b[14:]}
	for i := 0; f.EtherType == 0x8100 || f.EtherType == 0x88a8; i++ {
		if i >= 2 || len(f.Payload) < 4 {
			return Frame{}, errors.New("invalid VLAN header")
		}
		f.Tagged = true
		f.EtherType = binary.BigEndian.Uint16(f.Payload[2:4])
		f.Payload = f.Payload[4:]
	}
	return f, nil
}

type Datagram struct {
	Source, Destination         netip.Addr
	SourcePort, DestinationPort uint16
	HopLimit                    uint8
	Protocol                    uint8
	Payload                     []byte
}

func IP(f Frame) (Datagram, error) {
	p := f.Payload
	var d Datagram
	switch f.EtherType {
	case 0x800:
		if len(p) < 20 || p[0]>>4 != 4 {
			return d, errors.New("short IPv4")
		}
		h := int(p[0]&15) * 4
		n := int(binary.BigEndian.Uint16(p[2:4]))
		if h < 20 || n < h || n > len(p) || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
			return d, errors.New("invalid or fragmented IPv4")
		}
		if Checksum(p[:h]) != 0 {
			return d, errors.New("invalid IPv4 checksum")
		}
		d.Source = netip.AddrFrom4([4]byte(p[12:16]))
		d.Destination = netip.AddrFrom4([4]byte(p[16:20]))
		d.HopLimit = p[8]
		d.Protocol = p[9]
		d.Payload = p[h:n]
	case 0x86dd:
		if len(p) < 40 || p[0]>>4 != 6 {
			return d, errors.New("short IPv6")
		}
		n := 40 + int(binary.BigEndian.Uint16(p[4:6]))
		if n > len(p) {
			return d, errors.New("truncated IPv6")
		}
		d.Source = netip.AddrFrom16([16]byte(p[8:24]))
		d.Destination = netip.AddrFrom16([16]byte(p[24:40]))
		d.HopLimit = p[7]
		d.Protocol = p[6]
		d.Payload = p[40:n]

		for i := 0; d.Protocol == 0 || d.Protocol == 43 || d.Protocol == 60; i++ {
			if i >= 4 || len(d.Payload) < 8 {
				return d, errors.New("invalid extension chain")
			}
			n := (int(d.Payload[1]) + 1) * 8
			if n > len(d.Payload) {
				return d, errors.New("short extension")
			}
			d.Protocol = d.Payload[0]
			d.Payload = d.Payload[n:]
		}
		if d.Protocol == 44 {
			return d, errors.New("fragmented IPv6")
		}
	default:
		return d, errors.New("not IP")
	}
	return d, nil
}

func UDP(d Datagram) (Datagram, error) {
	if d.Protocol != 17 || len(d.Payload) < 8 {
		return d, errors.New("not UDP")
	}
	p := d.Payload
	n := int(binary.BigEndian.Uint16(p[4:6]))
	if n < 8 || n > len(p) {
		return d, errors.New("invalid UDP length")
	}
	d.SourcePort = binary.BigEndian.Uint16(p[:2])
	d.DestinationPort = binary.BigEndian.Uint16(p[2:4])
	d.Payload = p[8:n]
	return d, nil
}

func Checksum(parts ...[]byte) uint16 {
	var sum uint32
	var odd bool
	var pending byte
	for _, b := range parts {
		for _, v := range b {
			if !odd {
				pending = v
				odd = true
			} else {
				sum += uint32(pending)<<8 | uint32(v)
				odd = false
			}
		}
	}
	if odd {
		sum += uint32(pending) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ICMPv6Valid(d Datagram) bool {
	if !d.Source.Is6() || !d.Destination.Is6() || d.Protocol != 58 {
		return false
	}
	var pseudo [8]byte
	binary.BigEndian.PutUint32(pseudo[:4], uint32(len(d.Payload)))
	pseudo[7] = 58
	return Checksum(d.Source.AsSlice(), d.Destination.AsSlice(), pseudo[:], d.Payload) == 0
}

func IPv4UDP(srcMAC, dstMAC net.HardwareAddr, src, dst netip.Addr, sport, dport uint16, payload []byte) ([]byte, error) {
	if len(srcMAC) != 6 || len(dstMAC) != 6 || !src.Is4() || !dst.Is4() || len(payload) > 1472 {
		return nil, errors.New("invalid IPv4 UDP frame")
	}
	b := make([]byte, 14+20+8+len(payload))
	copy(b, dstMAC)
	copy(b[6:], srcMAC)
	binary.BigEndian.PutUint16(b[12:], 0x800)
	ip := b[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(b)-14))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:], src.AsSlice())
	copy(ip[16:], dst.AsSlice())
	binary.BigEndian.PutUint16(ip[10:], Checksum(ip))
	u := b[34:]
	binary.BigEndian.PutUint16(u, sport)
	binary.BigEndian.PutUint16(u[2:], dport)
	binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
	copy(u[8:], payload)
	pseudo := []byte{0, 17, byte(len(u) >> 8), byte(len(u))}
	cs := Checksum(src.AsSlice(), dst.AsSlice(), pseudo, u)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], cs)
	return b, nil
}
