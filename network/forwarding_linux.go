package network

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ForwardingReady(iface string, ipv4, ipv6 bool) error {
	paths := map[string]string{}
	if ipv4 {
		paths["net/ipv4/conf/"+iface+"/forwarding"] = "1"
		paths["net/ipv4/conf/"+iface+"/send_redirects"] = "0"
		paths["net/ipv4/conf/all/send_redirects"] = "0"
	}
	if ipv6 {
		paths["net/ipv6/conf/all/forwarding"] = "1"
		paths["net/ipv6/conf/"+iface+"/forwarding"] = "1"
		paths["net/ipv6/conf/"+iface+"/accept_ra"] = "2"
	}
	for path, want := range paths {
		b, err := os.ReadFile(filepath.Join("/proc/sys", path))
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(b)) != want {
			return fmt.Errorf("forwarding requires %s=%s; configure it explicitly on the host", strings.ReplaceAll(path, "/", "."), want)
		}
	}
	return nil
}
