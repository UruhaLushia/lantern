package discovery

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/UruhaLushia/lantern/device"
	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/UruhaLushia/lantern/internal/wincapture"
	"golang.org/x/sys/windows"
)

var sendARP = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SendARP")

// StartIPv4Observer shares a gateway's existing receiver. It creates no raw
// socket, loads no driver and detaches synchronously before Close returns.
func StartIPv4Observer(ctx context.Context, iface net.Interface, opts Options, store *device.Store, source interface{ SetPacketObserver(func([]byte)) }) (*Service, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	local, err := localIPv4(iface)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Service{iface: iface, opts: opts, store: store, cancel: cancel, done: make(chan struct{}), status: Status{Running: true}}
	if s.opts.AddressTTL <= 0 {
		s.opts.AddressTTL = 10 * time.Minute
	}
	s.closeNative = func() error { source.SetPacketObserver(nil); return nil }
	locals := map[netip.Addr]bool{local: true}
	if addresses, err := iface.Addrs(); err == nil {
		for _, address := range addresses {
			if p, err := netip.ParsePrefix(address.String()); err == nil {
				locals[p.Addr()] = true
			}
		}
	}
	source.SetPacketObserver(func(packet []byte) {
		if len(packet) >= 20 && locals[netip.AddrFrom4([4]byte(packet[12:16]))] {
			return
		}
		if ctx.Err() == nil {
			s.processNativeIPv4(packet, local)
		}
	})
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		s.status.Running = false
		s.mu.Unlock()
		close(s.done)
	}()
	return s, nil
}

func localIPv4(iface net.Interface) (netip.Addr, error) {
	addresses, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, address := range addresses {
		p, err := netip.ParsePrefix(address.String())
		if err == nil && p.Addr().Is4() && p.Addr().IsGlobalUnicast() {
			return p.Addr(), nil
		}
	}
	return netip.Addr{}, errors.New("discovery needs an existing LAN IPv4 address")
}

func Start(ctx context.Context, iface net.Interface, opts Options, store *device.Store) (*Service, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	local, err := localIPv4(iface)
	if err != nil {
		return nil, err
	}
	rx, err := wincapture.Open(local)
	if err != nil {
		return nil, err
	}
	if opts.AddressTTL <= 0 {
		opts.AddressTTL = 10 * time.Minute
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Service{iface: iface, opts: opts, store: store, cancel: cancel, closeNative: rx.Close, done: make(chan struct{}), status: Status{Running: true}}
	locals := map[netip.Addr]bool{local: true}
	if addresses, err := iface.Addrs(); err == nil {
		for _, address := range addresses {
			if p, err := netip.ParsePrefix(address.String()); err == nil {
				locals[p.Addr()] = true
			}
		}
	}
	go func() {
		defer close(s.done)
		defer func() { s.mu.Lock(); s.status.Running = false; s.mu.Unlock() }()
		buffer := make([]byte, 65535)
		for ctx.Err() == nil {
			n, err := rx.ReadPacket(buffer)
			if err != nil {
				if ctx.Err() == nil {
					s.mu.Lock()
					s.status.Problems = []string{err.Error()}
					s.mu.Unlock()
				}
				return
			}
			if n != 0 {
				if n >= 20 && locals[netip.AddrFrom4([4]byte(buffer[12:16]))] {
					continue
				}
				s.processNativeIPv4(buffer[:n], local)
			}
		}
	}()
	return s, nil
}

// Native IP capture deliberately provides no Ethernet header. Only the DHCP
// parser is shared; it records ClientHWAddr as a claim without inventing MACs.
func (s *Service) processNativeIPv4(p []byte, local netip.Addr) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 17 {
		return
	}
	h, n := int(p[0]&15)*4, int(binary.BigEndian.Uint16(p[2:4]))
	if h < 20 || n < h || n > len(p) || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
		return
	}
	d := ether.Datagram{Source: netip.AddrFrom4([4]byte(p[12:16])), Destination: netip.AddrFrom4([4]byte(p[16:20])), Protocol: 17, HopLimit: p[8], Payload: p[h:n]}
	if d.Source == local {
		return // Our replies must not be classified as a competing DHCP server.
	}
	d, err := ether.UDP(d)
	if err != nil || (d.SourcePort != 67 && d.SourcePort != 68) {
		return
	}
	s.dhcp(ether.Frame{EtherType: 0x800, Payload: p[:n]}, d)
}

// DHCP conflict probes use the built-in IP Helper ARP API, scoped by the LAN
// source address. All other Ethernet transmissions are unsupported on Windows.
func (s *Service) Send(frame []byte, _ net.HardwareAddr) error {
	f, err := ether.Parse(frame)
	if err != nil || f.EtherType != 0x806 || len(f.Payload) != 28 || binary.BigEndian.Uint16(f.Payload[6:8]) != 1 {
		return errors.New("Windows discovery only sends native IPv4 ARP probes")
	}
	local, err := localIPv4(s.iface)
	if err != nil {
		return err
	}
	target := netip.AddrFrom4([4]byte(f.Payload[24:28]))
	var mac [8]byte
	length := uint32(len(mac))
	result, _, _ := sendARP.Call(uintptr(binary.LittleEndian.Uint32(target.AsSlice())), uintptr(binary.LittleEndian.Uint32(local.AsSlice())), uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&length)))
	runtime.KeepAlive(&mac)
	if result == 0 && length == 6 {
		return s.store.Observe(device.Observation{Interface: s.iface.Name, MAC: net.HardwareAddr(mac[:6]), IP: target, Source: "arp", TTL: s.opts.AddressTTL})
	}
	if result == uintptr(windows.ERROR_BAD_NET_NAME) {
		return nil // No reply; allocation still waits its observation interval.
	}
	if result != 0 {
		return syscall.Errno(result)
	}
	return errors.New("native ARP returned an invalid hardware address")
}
