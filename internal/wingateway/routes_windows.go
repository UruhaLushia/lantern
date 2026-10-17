package wingateway

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"

	"github.com/UruhaLushia/lantern/network"
	"golang.org/x/sys/windows"
)

func verifyTUNRoute(tun network.WindowsInterface, destination netip.Addr) error {
	row := windows.MibIfRow2{InterfaceLuid: tun.LUID}
	if err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); err != nil {
		return err
	}
	if row.InterfaceGuid.String() != tun.GUID || row.InterfaceIndex != tun.Index || row.OperStatus != windows.IfOperStatusUp {
		return errors.New("TUN instance is no longer available; injection paused")
	}
	ipif := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: tun.LUID}
	if err := windows.GetIpInterfaceEntry(&ipif); err != nil {
		return err
	}
	if ipif.Connected == 0 || ipif.ForwardingEnabled == 0 {
		return errors.New("TUN return forwarding is unavailable")
	}
	if ipif.NlMtu != tun.IPv4.MTU {
		return errors.New("egress MTU changed; recreate the IPv4 datapath")
	}
	var index uint32
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: destination.As4()}, &index); err != nil {
		return err
	}
	if index != tun.Index {
		return errors.New("destination route no longer selects the verified TUN; injection paused")
	}
	return nil
}

func validateClient(lan network.WindowsInterface, client netip.Addr) error {
	if !client.Is4() || !client.IsGlobalUnicast() {
		return errors.New("client must have a unicast IPv4 address")
	}
	iface, err := net.InterfaceByIndex(int(lan.Index))
	if err != nil {
		return err
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return err
	}
	onLink := false
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		if prefix.Addr() == client {
			return errors.New("client address belongs to the gateway")
		}
		if prefix.Contains(client) {
			value := binary.BigEndian.Uint32(client.AsSlice())
			hostMask := uint32(0xffffffff) >> prefix.Bits()
			if prefix.Bits() <= 30 && (value&hostMask == 0 || value&hostMask == hostMask) {
				return errors.New("client cannot be a subnet network or broadcast address")
			}
			onLink = true
		}
	}
	if !onLink {
		return errors.New("client must be on the selected LAN's connected IPv4 subnet")
	}
	return verifyLAN(lan, client)
}

func verifyLAN(lan network.WindowsInterface, client netip.Addr) error {
	// Query only the selected native interface and IPv4 record. Re-enumerating
	// every adapter and querying IPv6 on every IPv4 packet adds unrelated work.
	row := windows.MibIfRow2{InterfaceLuid: lan.LUID}
	if err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); err != nil {
		return err
	}
	if row.InterfaceLuid != lan.LUID || row.InterfaceGuid.String() != lan.GUID || row.InterfaceIndex != lan.Index || row.OperStatus != windows.IfOperStatusUp {
		return errors.New("LAN instance or connection changed; injection stopped")
	}
	ipif := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: lan.LUID}
	if err := windows.GetIpInterfaceEntry(&ipif); err != nil {
		return err
	}
	if ipif.Connected == 0 || ipif.ForwardingEnabled != 0 {
		return errors.New("LAN instance or forwarding state changed; injection stopped")
	}
	var index uint32
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: client.As4()}, &index); err != nil {
		return err
	}
	if index != lan.Index {
		return errors.New("client return route does not select the LAN; injection stopped")
	}
	return nil
}
