package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/mdlayher/packet"
	"golang.org/x/sys/unix"
)

func ProbeDHCP(ctx context.Context, name string, timeout time.Duration) (result DHCPProbe, err error) {
	result = DHCPProbe{Interface: name, StartedAt: time.Now().UTC(), Servers: []DHCPServer{},
		Note: "Only responding servers on this LAN are listed. Silence does not prove absence; allowlists, relays or packet loss may hide servers. No lease was requested. Disable other DHCP services only when exclusive takeover is intended."}
	defer func() { result.FinishedAt = time.Now().UTC() }()
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	if timeout < time.Second || timeout > 10*time.Second {
		return result, errors.New("DHCP probe timeout must be 1s..10s")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return result, err
	}
	if len(iface.HardwareAddr) != 6 || iface.Flags&net.FlagUp == 0 || iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
		return result, errors.New("DHCP probe requires an up Ethernet LAN interface")
	}
	filter, err := ether.ControlFilter()
	if err != nil {
		return result, err
	}
	c, err := packet.Listen(iface, packet.Raw, unix.ETH_P_ALL, &packet.Config{Filter: filter})
	if err != nil {
		return result, err
	}
	defer c.Close()
	p, err := dhcpv4.NewDiscovery(iface.HardwareAddr)
	if err != nil {
		return result, err
	}
	p.SetBroadcast()
	broadcast := net.HardwareAddr{255, 255, 255, 255, 255, 255}
	send := func() error {
		frame, err := ether.IPv4UDP(iface.HardwareAddr, broadcast, netip.IPv4Unspecified(), netip.MustParseAddr("255.255.255.255"), 68, 67, p.ToBytes())
		if err != nil {
			return err
		}
		if err := c.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		if _, err := c.WriteTo(frame, &packet.Addr{HardwareAddr: broadcast}); err != nil {
			return err
		}
		result.DiscoveriesSent++
		return nil
	}
	if err := send(); err != nil {
		return result, err
	}
	end := time.Now().Add(timeout)
	retry := time.Now().Add(timeout / 2)
	buf := make([]byte, 2048)
	for time.Now().Before(end) {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if result.DiscoveriesSent == 1 && !time.Now().Before(retry) {
			p.NumSeconds = uint16(time.Since(result.StartedAt) / time.Second)
			if err := send(); err != nil {
				return result, err
			}
		}
		deadline := time.Now().Add(100 * time.Millisecond)
		if end.Before(deadline) {
			deadline = end
		}
		if err := c.SetReadDeadline(deadline); err != nil {
			return result, err
		}
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return result, err
		}
		f, err := ether.Parse(buf[:n])
		if err != nil || f.Tagged || f.EtherType != 0x800 {
			continue
		}
		d, err := ether.IP(f)
		if err != nil {
			continue
		}
		d, err = ether.UDP(d)
		if err != nil || d.SourcePort != 67 || d.DestinationPort != 68 {
			continue
		}
		offer, err := dhcpv4.FromBytes(d.Payload)
		if err != nil || offer.OpCode != dhcpv4.OpcodeBootReply || offer.MessageType() != dhcpv4.MessageTypeOffer || offer.TransactionID != p.TransactionID || !slices.Equal(offer.ClientHWAddr, iface.HardwareAddr) {
			continue
		}
		entry := describeDHCPServer(offer, f, d)
		i := slices.IndexFunc(result.Servers, func(v DHCPServer) bool { return sameDHCPServer(v, entry) })
		if i >= 0 {
			result.Servers[i] = entry
		} else if len(result.Servers) < 64 {
			result.Servers = append(result.Servers, entry)
		} else {
			result.Truncated = true
		}
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	sort.Slice(result.Servers, func(i, j int) bool {
		a, b := result.Servers[i], result.Servers[j]
		if a.Address != b.Address {
			return a.Address.Compare(b.Address) < 0
		}
		if a.SourceIP != b.SourceIP {
			return a.SourceIP.Compare(b.SourceIP) < 0
		}
		return a.MAC < b.MAC
	})
	return result, nil
}
