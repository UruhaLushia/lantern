// Package wincapture receives IPv4 packets using Windows' built-in Winsock
// SIO_RCVALL_IPLEVEL. It does not provide Ethernet addresses or direction.
package wincapture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Socket struct {
	mu     sync.Mutex
	handle windows.Handle
	open   bool
}

func Open(local netip.Addr) (_ *Socket, resultErr error) {
	if !local.Is4() || !local.IsGlobalUnicast() {
		return nil, errors.New("native capture requires an existing unicast IPv4 address")
	}
	var data windows.WSAData
	if err := windows.WSAStartup(0x202, &data); err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			_ = windows.WSACleanup()
		}
	}()
	h, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			_ = windows.Closesocket(h)
		}
	}()
	if err := windows.Bind(h, &windows.SockaddrInet4{Addr: local.As4()}); err != nil {
		return nil, err
	}
	if err := windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_RCVTIMEO, 20); err != nil {
		return nil, err
	}
	if err := mode(h, 3); err != nil {
		return nil, fmt.Errorf("SIO_RCVALL IPLEVEL: %w", err)
	}
	return &Socket{handle: h, open: true}, nil
}

func mode(h windows.Handle, value uint32) error {
	var input [4]byte
	binary.LittleEndian.PutUint32(input[:], value)
	var returned uint32
	return windows.WSAIoctl(h, 0x98000001, &input[0], 4, nil, 0, &returned, nil, 0)
}

// ReadPacket receives into caller-owned storage, avoiding a per-packet copy.
// A full IPv4-sized buffer is required so truncation cannot go unnoticed.
// It returns zero on timeout. No buffer is retained after this call returns.
func (s *Socket) ReadPacket(buffer []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readPacket(buffer)
}

// ReadAvailablePacket reads only when data is already queued. mu prevents a
// competing receive between FIONREAD and recvfrom. Socket mode is unchanged.
func (s *Socket) ReadAvailablePacket(buffer []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open {
		return 0, net.ErrClosed
	}
	if len(buffer) < 65535 {
		return 0, errors.New("native receive requires a 65535-byte buffer")
	}
	var available, returned uint32
	if err := windows.WSAIoctl(s.handle, 0x4004667f, nil, 0, (*byte)(unsafe.Pointer(&available)), 4, &returned, nil, 0); err != nil {
		return 0, err
	}
	if available == 0 {
		return 0, nil
	}
	return s.readPacket(buffer)
}

func (s *Socket) readPacket(buffer []byte) (int, error) {
	if !s.open {
		return 0, net.ErrClosed
	}
	if len(buffer) < 65535 {
		return 0, errors.New("native receive requires a 65535-byte buffer")
	}
	n, _, err := windows.Recvfrom(s.handle, buffer, 0)
	if errors.Is(err, windows.WSAETIMEDOUT) || errors.Is(err, windows.WSAEWOULDBLOCK) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if n < 20 || buffer[0]>>4 != 4 {
		return 0, errors.New("native receive returned a non-IPv4 packet")
	}
	return n, nil
}

func (s *Socket) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open {
		return nil
	}
	modeErr := mode(s.handle, 0)
	if err := windows.Closesocket(s.handle); err != nil {
		return errors.Join(modeErr, err)
	}
	s.open = false
	return errors.Join(modeErr, windows.WSACleanup())
}
