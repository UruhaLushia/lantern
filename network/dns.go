//go:build !windows

package network

import (
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
)

func systemDNS() []netip.Addr {
	paths := []string{"/etc/resolv.conf"}
	if runtime.GOOS == "linux" {
		paths = append([]string{"/run/NetworkManager/resolv.conf", "/run/systemd/resolve/resolv.conf"}, paths...)
	}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var servers []netip.Addr
		for line := range strings.SplitSeq(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "nameserver" {
				continue
			}
			ip, err := netip.ParseAddr(fields[1])
			if err == nil && ip.IsGlobalUnicast() && !ip.IsLoopback() && !slices.Contains(servers, ip) {
				servers = append(servers, ip)
			}
		}
		if len(servers) > 0 {
			return servers
		}
	}
	return []netip.Addr{}
}
