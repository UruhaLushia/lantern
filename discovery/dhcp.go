package discovery

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

type DHCPProbe struct {
	Interface       string       `json:"interface"`
	StartedAt       time.Time    `json:"started_at"`
	FinishedAt      time.Time    `json:"finished_at"`
	DiscoveriesSent int          `json:"discoveries_sent"`
	Servers         []DHCPServer `json:"servers"`
	Truncated       bool         `json:"truncated"`
	Note            string       `json:"note"`
}

func describeDHCPServer(p *dhcpv4.DHCPv4, f ether.Frame, d ether.Datagram) DHCPServer {
	server := addr(p.ServerIdentifier())
	if !server.IsValid() || server.IsUnspecified() {
		server = d.Source
	}
	v := DHCPServer{Address: server, MAC: f.SourceMAC.String(), SourceIP: d.Source,
		Routers: addrs(p.Router()), DNS: addrs(p.DNS()), LastSeen: time.Now().UTC(),
		Lease: p.IPAddressLeaseTime(0), MessageType: p.MessageType().String()}
	if a := addr(p.GatewayIPAddr); a.IsValid() && !a.IsUnspecified() {
		v.RelayIP = a
	}
	if a := addr(p.YourIPAddr); a.IsValid() && !a.IsUnspecified() {
		v.OfferedIP = a
	}
	if m := p.SubnetMask(); len(m) == 4 {
		v.SubnetMask = netip.AddrFrom4([4]byte(m))
	}
	v.TakeoverHint = fmt.Sprintf("For exclusive Lantern DHCP, disable DHCP on server %s; observed source %s, Ethernet sender %s. For coexistence, verify disjoint pools and reservations.", v.Address, v.SourceIP, v.MAC)
	if v.RelayIP.IsValid() || v.SourceIP != v.Address {
		v.TakeoverHint += " The Ethernet sender may be a relay/next hop; locate the server by its server identifier, not this MAC alone."
	}
	return v
}

func sameDHCPServer(a, b DHCPServer) bool {
	return a.Address == b.Address && a.SourceIP == b.SourceIP && a.MAC == b.MAC && a.RelayIP == b.RelayIP
}
