package lantern

import (
	"net/netip"
	"time"
)

// WindowsGatewayOptions opts into the Windows IPv4 injection datapath. The LAN
// must have forwarding disabled; EgressInterface is only inspected, never
// opened as a TUN session or reconfigured. Driver loading is separately opt-in.
type WindowsGatewayOptions struct {
	LocalIPv4       netip.Addr
	EgressInterface string
	DriverDirectory string
	AllowDriverLoad bool
	Clients         []netip.Addr
	BatchSize       int
}

// IPv4GatewayStatus reports the explicitly managed Windows packet datapath.
// Unix uses system forwarding and reports its readiness through Problems.
type IPv4GatewayStatus struct {
	Running     bool   `json:"running"`
	Forwarded   uint64 `json:"forwarded"`
	SendCalls   uint64 `json:"send_calls"`
	SelfIgnored uint64 `json:"self_ignored"`
	Dropped     uint64 `json:"dropped"`
	LastError   string `json:"last_error,omitempty"`
}

type platformDatapath interface {
	Ready() error
	SetLease(string, netip.Addr, time.Time, bool) error
	ClearLeases()
	Close() error
	Snapshot() IPv4GatewayStatus
}
