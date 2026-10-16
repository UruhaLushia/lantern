package ether

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

type bpfSocket struct {
	mu          sync.RWMutex
	readMu      sync.Mutex
	fd          int
	iface       *net.Interface
	buffer      []byte
	pending     []byte
	readUntil   time.Time
	writeUntil  time.Time
	memberships []net.PacketConn
}

func Listen(iface *net.Interface) (_ Socket, err error) {
	if len(iface.Name) >= unix.IFNAMSIZ {
		return nil, errors.New("interface name is too long")
	}
	fd := -1
	for i := range 256 {
		fd, err = unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EBUSY) {
			return nil, fmt.Errorf("open BPF device: %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("no available BPF device: %w", err)
	}
	defer func() {
		if err != nil {
			_ = unix.Close(fd)
		}
	}()
	var ifreq [32]byte
	copy(ifreq[:unix.IFNAMSIZ], iface.Name)
	if err = bpfIoctl(fd, unix.BIOCSETIF, unsafe.Pointer(&ifreq)); err != nil {
		return nil, fmt.Errorf("bind BPF to %s: %w", iface.Name, err)
	}
	dlt, err := unix.IoctlGetInt(fd, unix.BIOCGDLT)
	if err != nil {
		return nil, err
	}
	if dlt != unix.DLT_EN10MB {
		return nil, fmt.Errorf("interface %s does not expose Ethernet frames (DLT %d)", iface.Name, dlt)
	}
	for _, setting := range []struct {
		request uint
		value   int
	}{{unix.BIOCIMMEDIATE, 1}, {unix.BIOCSHDRCMPLT, 1}, {unix.BIOCSSEESENT, 0}} {
		if err = unix.IoctlSetPointerInt(fd, setting.request, setting.value); err != nil {
			return nil, err
		}
	}
	filter, err := ControlFilter()
	if err != nil {
		return nil, err
	}
	insns := make([]unix.BpfInsn, len(filter))
	for i, ins := range filter {
		insns[i] = unix.BpfInsn{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	program := unix.BpfProgram{Len: uint32(len(insns)), Insns: &insns[0]}
	if err = bpfIoctl(fd, unix.BIOCSETF, unsafe.Pointer(&program)); err != nil {
		return nil, err
	}
	size, err := unix.IoctlGetInt(fd, unix.BIOCGBLEN)
	if err != nil {
		return nil, err
	}
	if size < unix.SizeofBpfHdr || size > 16<<20 {
		return nil, fmt.Errorf("invalid BPF buffer size %d", size)
	}
	return &bpfSocket{fd: fd, iface: iface, buffer: make([]byte, size)}, nil
}

func bpfIoctl(fd int, request uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(arg))
	runtime.KeepAlive(arg)
	if errno != 0 {
		return errno
	}
	return nil
}

func (c *bpfSocket) JoinGroup(mac net.HardwareAddr) error {
	groups := map[string]string{
		"33:33:00:00:00:01": "ff02::1", "33:33:00:00:00:02": "ff02::2",
		"33:33:00:00:00:fb": "ff02::fb", "33:33:00:00:00:0c": "ff02::c",
		"01:00:5e:00:00:fb": "224.0.0.251", "01:00:5e:7f:ff:fa": "239.255.255.250",
	}
	ip := net.ParseIP(groups[mac.String()])
	if ip == nil {
		return fmt.Errorf("unsupported multicast group %s", mac)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return net.ErrClosed
	}
	var conn net.PacketConn
	var err error
	if ip.To4() != nil {
		conn, err = net.ListenPacket("udp4", "0.0.0.0:0")
		if err == nil {
			err = ipv4.NewPacketConn(conn).JoinGroup(c.iface, &net.UDPAddr{IP: ip})
		}
	} else {
		conn, err = net.ListenPacket("udp6", "[::]:0")
		if err == nil {
			err = ipv6.NewPacketConn(conn).JoinGroup(c.iface, &net.UDPAddr{IP: ip})
		}
	}
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return err
	}
	c.memberships = append(c.memberships, conn)
	return nil
}

func (c *bpfSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		c.mu.RLock()
		if c.fd < 0 {
			c.mu.RUnlock()
			return 0, nil, net.ErrClosed
		}
		if !c.readUntil.IsZero() && !time.Now().Before(c.readUntil) {
			c.mu.RUnlock()
			return 0, nil, os.ErrDeadlineExceeded
		}
		if len(c.pending) != 0 {
			c.mu.RUnlock()
			if len(c.pending) < 18 {
				return 0, nil, errors.New("short BPF record header")
			}
			hdr := int(binary.NativeEndian.Uint16(c.pending[16:18]))
			caplen := int(binary.NativeEndian.Uint32(c.pending[8:12]))
			datalen := int(binary.NativeEndian.Uint32(c.pending[12:16]))
			if hdr < 18 || hdr > len(c.pending) || caplen > len(c.pending)-hdr {
				return 0, nil, errors.New("invalid BPF record length")
			}
			frame := c.pending[hdr : hdr+caplen]
			// Darwin aligns BPF records to a 32-bit boundary, including on arm64.
			next := (hdr + caplen + 3) &^ 3
			c.pending = c.pending[min(next, len(c.pending)):]
			if caplen != datalen {
				continue
			}
			if len(b) < caplen {
				return 0, nil, io.ErrShortBuffer
			}
			return copy(b, frame), nil, nil
		}
		wait := 100
		if !c.readUntil.IsZero() {
			wait = min(wait, max(1, int(time.Until(c.readUntil).Milliseconds())))
		}
		poll := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLIN}}
		_, err := unix.Poll(poll, wait)
		if err == nil && poll[0].Revents != 0 {
			var n int
			n, err = unix.Read(c.fd, c.buffer)
			if n > 0 {
				c.pending = c.buffer[:n]
			}
		}
		c.mu.RUnlock()
		if err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return 0, nil, err
		}
	}
}

func (c *bpfSocket) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.fd < 0 {
		return 0, net.ErrClosed
	}
	if !c.writeUntil.IsZero() && !time.Now().Before(c.writeUntil) {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := unix.Write(c.fd, b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (c *bpfSocket) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readUntil = t
	return nil
}

func (c *bpfSocket) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeUntil = t
	return nil
}

func (c *bpfSocket) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return net.ErrClosed
	}
	err := unix.Close(c.fd)
	c.fd = -1
	for _, conn := range c.memberships {
		err = errors.Join(err, conn.Close())
	}
	c.memberships = nil
	return err
}
