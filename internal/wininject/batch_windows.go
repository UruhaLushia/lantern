package wininject

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"unsafe"
)

// Below WinDivert's 255-packet limit to bound memory and ambiguous completions.
const maxBatchPackets = 16

func batchSize(packets [][]byte) (int, error) {
	if len(packets) == 0 || len(packets) > maxBatchPackets {
		return 0, errors.New("injection batch requires 1..16 IPv4 packets")
	}
	total := 0
	for _, p := range packets {
		if len(p) < 20 || len(p) > 65535 || p[0]>>4 != 4 || int(p[0]&15)*4 < 20 ||
			int(p[0]&15)*4 > len(p) || int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
			return 0, errors.New("batch requires complete, individually bounded IPv4 packets")
		}
		total += len(p)
	}
	return total, nil
}

func packBatch(dst []byte, packets [][]byte) ([]byte, error) {
	total, err := batchSize(packets)
	if err != nil {
		return nil, err
	}
	if cap(dst) < total {
		dst = make([]byte, 0, total)
	}
	dst = dst[:0]
	for _, p := range packets {
		dst = append(dst, p...)
	}
	return dst, nil
}

// SendBatch packs IPv4 packets with one 80-byte address each. flags=0 and
// overlapped=NULL select the synchronous DLL wait. It never retries: a failed
// call can already have injected an unknown subset. Success is API acceptance.
func (s *Sender) SendBatch(packets [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == 0 {
		return net.ErrClosed
	}
	packed, err := packBatch(s.batch, packets)
	if err != nil {
		return err
	}
	s.batch = packed
	total := len(packed)
	offset := 0
	for i, p := range packets {
		a := &s.batchAddresses[i]
		*a = Address{Flags: 1 << 17}
		ok, _, err := s.checksums.Call(uintptr(unsafe.Pointer(&s.batch[offset])), uintptr(len(p)), uintptr(unsafe.Pointer(a)), 0)
		if ok == 0 {
			return fmt.Errorf("batch checksum preparation: %w", err)
		}
		offset += len(p)
	}
	var sent uint32
	ok, _, callErr := s.sendEx.Call(s.handle, uintptr(unsafe.Pointer(&s.batch[0])), uintptr(total),
		uintptr(unsafe.Pointer(&sent)), 0, uintptr(unsafe.Pointer(&s.batchAddresses[0])),
		uintptr(len(packets))*unsafe.Sizeof(Address{}), 0)
	// The audited driver copies input before completing I/O; its later WFP
	// callback owns its own allocation, never the Go scratch buffers.
	runtime.KeepAlive(s.batch)
	runtime.KeepAlive(&s.batchAddresses)
	if ok == 0 {
		return fmt.Errorf("WinDivertSendEx failed; some batch packets may already be submitted, no retry: %w", callErr)
	}
	if sent != uint32(total) {
		return fmt.Errorf("short batch submission (%d/%d bytes); some packets may already be submitted, no retry", sent, total)
	}
	return nil
}
