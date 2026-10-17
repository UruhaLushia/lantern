package network

import (
	"errors"
	"net/netip"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

func systemDNS() []netip.Addr {
	servers := []netip.Addr{}
	size := uint32(15 << 10)
	// The required size can change while adapters are being recreated.
	for range 3 {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return servers
		}
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp {
				continue
			}
			for dns := a.FirstDnsServerAddress; dns != nil; dns = dns.Next {
				ip, ok := netip.AddrFromSlice(dns.Address.IP())
				if !ok {
					continue
				}
				ip = ip.Unmap()
				if ip.Is6() && ip.IsLinkLocalUnicast() {
					ip = ip.WithZone(windows.UTF16PtrToString(a.FriendlyName))
				}
				if !ip.IsUnspecified() && !ip.IsMulticast() && !slices.Contains(servers, ip) {
					servers = append(servers, ip)
				}
			}
		}
		return servers
	}
	return servers
}
