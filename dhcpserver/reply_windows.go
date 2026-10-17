package dhcpserver

import (
	"errors"
	"net"

	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

func sendReplyFrame(s *Service, frame []byte, _ net.HardwareAddr) error {
	f, err := ether.Parse(frame)
	if err != nil {
		return err
	}
	d, err := ether.IP(f)
	if err != nil {
		return err
	}
	d, err = ether.UDP(d)
	if err != nil {
		return err
	}
	p, err := dhcpv4.FromBytes(d.Payload)
	if err != nil {
		return err
	}
	// With no ciaddr the client may not answer ARP yet. Windows' UDP API has
	// no Ethernet-unicast primitive, so broadcast the initial OFFER/ACK.
	dst := p.ClientIPAddr
	if dst.To4() == nil || dst.IsUnspecified() {
		dst = net.IPv4bcast
	}
	n, err := s.socket.WriteTo(d.Payload, &net.UDPAddr{IP: dst, Port: 68})
	if err == nil && n != len(d.Payload) {
		return errors.New("short DHCP UDP send")
	}
	return err
}
