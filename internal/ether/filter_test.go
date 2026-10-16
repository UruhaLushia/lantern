package ether

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/bpf"
)

func TestControlFilter(t *testing.T) {
	raw, err := ControlFilter()
	if err != nil {
		t.Fatal(err)
	}
	ins, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("invalid BPF instructions")
	}
	vm, err := bpf.NewVM(ins)
	if err != nil {
		t.Fatal(err)
	}
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	for _, tc := range []struct {
		name         string
		sport, dport uint16
		protocol     byte
		fragment     bool
		accept       bool
	}{
		{"DHCP client", 68, 67, 17, false, true},
		{"DHCP server", 67, 68, 17, false, true},
		{"mDNS reply", 5353, 50000, 17, false, true},
		{"SSDP discovery", 50000, 1900, 17, false, true},
		{"ordinary UDP", 50000, 443, 17, false, false},
		{"TCP", 68, 67, 6, false, false},
		{"fragmented DHCP", 68, 67, 17, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := IPv4UDP(mac, mac, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), tc.sport, tc.dport, []byte("payload"))
			if err != nil {
				t.Fatal(err)
			}
			b[23] = tc.protocol
			if tc.fragment {
				b[20] = 0x20
			}
			n, err := vm.Run(b)
			if err != nil || (n > 0) != tc.accept {
				t.Fatalf("filter=%d, err=%v, want accept=%v", n, err, tc.accept)
			}
			for i := range b {
				if _, err := vm.Run(slices.Clone(b[:i])); err != nil {
					t.Fatalf("short frame length %d: %v", i, err)
				}
			}
		})
	}
}
