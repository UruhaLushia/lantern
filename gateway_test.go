package lantern

import (
	"strings"
	"testing"
)

func TestGatewayConfigurationRequiresWindowsDatapath(t *testing.T) {
	for _, dhcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "static clients", true: "DHCP clients"}[dhcp], func(t *testing.T) {
			opts := Options{WindowsGateway: &WindowsGatewayOptions{}}
			opts.DHCP.Enabled = dhcp
			s := Status{IPv4Gateway: IPv4GatewayStatus{LastError: "egress interface changed"}}
			s.DHCP.Running = dhcp
			err := gatewayConfigurationError(opts, s)
			if err == nil || !strings.Contains(err.Error(), s.IPv4Gateway.LastError) {
				t.Fatalf("unavailable datapath accepted or diagnostic lost: %v", err)
			}
			s.IPv4Gateway.Running = true
			s.IPv4Gateway.LastError = ""
			if err := gatewayConfigurationError(opts, s); err != nil {
				t.Fatalf("ready datapath rejected: %v", err)
			}
			if dhcp {
				s.DHCP.Running = false
				if err := gatewayConfigurationError(opts, s); err == nil {
					t.Fatal("ready datapath hid failed DHCP startup")
				}
			}
		})
	}
}

func TestGatewayConfigurationDoesNotRequireManagedUnixDatapath(t *testing.T) {
	opts := Options{}
	opts.DHCP.Enabled = true
	s := Status{}
	s.DHCP.Running = true
	if err := gatewayConfigurationError(opts, s); err != nil {
		t.Fatalf("Unix system forwarding requires no managed Windows datapath: %v", err)
	}
}
