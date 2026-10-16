package dhcpserver

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
)

type Reservation struct {
	MAC string     `json:"mac"`
	IP  netip.Addr `json:"ip"`
}

func NormalizeReservations(bindings []Reservation) ([]Reservation, error) {
	if len(bindings) > 65536 {
		return nil, errors.New("DHCP reservations exceed 65536 addresses")
	}
	bindings = slices.Clone(bindings)
	macs, ips := map[string]bool{}, map[netip.Addr]bool{}
	for i := range bindings {
		r := &bindings[i]
		mac, err := net.ParseMAC(r.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || slices.Equal(mac, make([]byte, 6)) {
			return nil, errors.New("DHCP reservations require unicast Ethernet MACs")
		}
		r.MAC = mac.String()
		if !r.IP.Is4() || !r.IP.IsGlobalUnicast() || r.IP == netip.MustParseAddr("255.255.255.255") {
			return nil, errors.New("DHCP reservations require IPv4 unicast addresses")
		}
		if macs[r.MAC] || ips[r.IP] {
			return nil, fmt.Errorf("duplicate DHCP reservation MAC or IP: %s / %s", r.MAC, r.IP)
		}
		macs[r.MAC], ips[r.IP] = true, true
	}
	return bindings, nil
}

func (s *Service) reservedIP(mac string) netip.Addr {
	return s.reservedByMAC[mac]
}

func (s *Service) reservedMAC(ip netip.Addr) string {
	return s.reservedByIP[ip]
}

func (s *Service) managed(ip netip.Addr) bool { return s.inPool(ip) || s.reservedMAC(ip) != "" }

func (s *Service) assignable(mac string, ip netip.Addr) bool {
	if s.excluded[ip] {
		return false
	}
	if fixed := s.reservedIP(mac); fixed.IsValid() {
		return fixed == ip
	}
	return s.inPool(ip) && s.reservedMAC(ip) == ""
}
