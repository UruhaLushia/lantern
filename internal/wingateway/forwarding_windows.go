package wingateway

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"net/netip"
	"time"
)

func (s *Service) forward(ctx context.Context) error {
	local := netip.MustParseAddr(s.opts.LocalIPv4)
	buffer := make([]byte, 65535)
	buffers := make([][]byte, s.opts.BatchSize)
	for i := range buffers {
		buffers[i] = make([]byte, 0, 65535)
	}
	packets := make([][]byte, 0, len(buffers))
	seen := newRecentPackets()
	fragmentBuffer := make([]byte, 0, 65535)
	checkAt := time.Time{}
	for ctx.Err() == nil {
		if !time.Now().Before(checkAt) {
			if err := verifyTUNRoute(s.egress, netip.MustParseAddr("1.1.1.1")); err != nil {
				return err
			}
			if err := verifyLAN(s.lan, local); err != nil {
				return err
			}
			checkAt = time.Now().Add(250 * time.Millisecond)
		}
		n, err := s.rx.ReadPacket(buffer)
		if err != nil {
			return err
		}
		packets = packets[:0]
		for observed := 0; n != 0 && observed < 64; observed++ {
			packet := buffer[:n]
			s.observe(packet)
			if len(packet) >= 20 {
				source := netip.AddrFrom4([4]byte(packet[12:16]))
				until, allowed := (*s.sources.Load())[source]
				allowed = allowed && (until.IsZero() || time.Now().Before(until))
				destination := netip.AddrFrom4([4]byte(packet[16:20]))
				for _, prefix := range s.lanPrefixes {
					if prefix.Contains(destination) {
						allowed = false // Direct LAN/local delivery belongs to Windows.
					}
				}
				if allowed {
					if seen.contains(packet) {
						s.selfIgnored.Add(1)
					} else if prepared, err := prepareForEgress(buffers[len(packets)], packet, source, local, s.egress.IPv4.MTU); err != nil {
						s.dropped.Add(1)
					} else {
						buffers[len(packets)] = prepared[:0]
						packets = append(packets, prepared)
					}
				}
			}
			if len(packets) == cap(packets) || ctx.Err() != nil || observed == 63 {
				break
			}
			n, err = s.rx.ReadAvailablePacket(buffer)
			if err != nil {
				return err
			}
		}
		if len(packets) == 0 || ctx.Err() != nil {
			continue
		}
		oversized := false
		for _, p := range packets {
			oversized = oversized || (s.egress.IPv4.MTU >= 68 && uint32(len(p)) > s.egress.IPv4.MTU)
		}
		if oversized {
			for _, p := range packets {
				if uint32(len(p)) <= s.egress.IPv4.MTU {
					if err := s.submit([][]byte{p}, seen, local); err != nil {
						return err
					}
					continue
				}
				for offset := 0; offset < len(p)-int(p[0]&15)*4; {
					if ctx.Err() != nil {
						return nil
					}
					fragment, next, err := fragmentIPv4Into(fragmentBuffer, p, offset, int(s.egress.IPv4.MTU))
					if err != nil {
						return err
					}
					if err := s.submit([][]byte{fragment}, seen, local); err != nil {
						return err
					}
					fragmentBuffer = fragment[:0]
					offset = next
				}
			}
			continue
		}
		if err := s.submit(packets, seen, local); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) submit(packets [][]byte, seen *recentPackets, local netip.Addr) error {
	for _, packet := range packets {
		var index uint32
		if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte(packet[16:20])}, &index); err != nil {
			return err
		}
		expected := s.egress.Index
		if netip.AddrFrom4([4]byte(packet[12:16])) == local {
			expected = s.lan.Index // Locally generated ICMP error to the client.
		}
		if index != expected {
			return fmt.Errorf("IPv4 destination route selects interface %d instead of verified egress %d; stopped", index, s.egress.Index)
		}
		seen.add(packet)
	}
	s.sendCalls.Add(1)
	var err error
	if len(packets) == 1 {
		err = s.tx.Send(packets[0])
	} else {
		err = s.tx.SendBatch(packets)
	}
	if err != nil {
		return err // A failed native submission is never retried.
	}
	s.forwarded.Add(uint64(len(packets)))
	return nil
}
