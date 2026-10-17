package network

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"
)

// WindowsIPInterface describes settings, not verified forwarding capability.
type WindowsIPInterface struct {
	Family          string `json:"family"`
	Metric          uint32 `json:"metric"`
	MTU             uint32 `json:"mtu"`
	Connected       bool   `json:"connected"`
	Forwarding      bool   `json:"forwarding"`
	WeakHostSend    bool   `json:"weak_host_send"`
	WeakHostReceive bool   `json:"weak_host_receive"`
	Error           string `json:"error,omitempty"`
}

// WindowsInterface keeps the native identity alongside both address families.
// Interface indexes and LUIDs must be rediscovered after adapter recreation.
type WindowsInterface struct {
	Name        string             `json:"name"`
	Index       uint32             `json:"index"`
	LUID        uint64             `json:"luid"`
	GUID        string             `json:"guid"`
	Description string             `json:"description"`
	Physical    bool               `json:"physical"`
	IPv4        WindowsIPInterface `json:"ipv4"`
	IPv6        WindowsIPInterface `json:"ipv6"`
}

// InspectWindowsInterface reads IP Helper state without changing host settings.
// An unavailable address family has its own Error; it does not hide the other.
func InspectWindowsInterface(name string) (WindowsInterface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return WindowsInterface{}, err
	}
	row := windows.MibIfRow2{InterfaceIndex: uint32(iface.Index)}
	if err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); err != nil {
		return WindowsInterface{}, fmt.Errorf("GetIfEntry2Ex %s: %w", name, err)
	}
	return WindowsInterface{Name: name, Index: row.InterfaceIndex, LUID: row.InterfaceLuid,
		GUID: row.InterfaceGuid.String(), Description: windows.UTF16ToString(row.Description[:]),
		Physical: physicalWindows(row), IPv4: inspectWindowsIP(row.InterfaceLuid, windows.AF_INET),
		IPv6: inspectWindowsIP(row.InterfaceLuid, windows.AF_INET6)}, nil
}

func inspectWindowsIP(luid uint64, family uint16) WindowsIPInterface {
	s := WindowsIPInterface{Family: "IPv4"}
	if family == windows.AF_INET6 {
		s.Family = "IPv6"
	}
	row := windows.MibIpInterfaceRow{Family: family, InterfaceLuid: luid}
	if err := windows.GetIpInterfaceEntry(&row); err != nil {
		s.Error = fmt.Sprintf("GetIpInterfaceEntry LUID %d %s: %v", luid, s.Family, err)
		return s
	}
	s.Metric, s.MTU = row.Metric, row.NlMtu
	s.Connected, s.Forwarding = row.Connected != 0, row.ForwardingEnabled != 0
	s.WeakHostSend, s.WeakHostReceive = row.WeakHostSend != 0, row.WeakHostReceive != 0
	return s
}
