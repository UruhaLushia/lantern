package device

import (
	"net/netip"
	"time"
)

type Confidence string

const (
	Observed Confidence = "observed"
	Inferred Confidence = "inferred"
)

type Evidence struct {
	Field      string     `json:"field"`
	Value      string     `json:"value"`
	Source     string     `json:"source"`
	Confidence Confidence `json:"confidence"`
	ObservedAt time.Time  `json:"observed_at"`
}

type Address struct {
	IP        netip.Addr `json:"ip"`
	Source    string     `json:"source"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type Device struct {
	Interface string     `json:"interface"`
	MAC       string     `json:"mac"`
	Addresses []Address  `json:"addresses"`
	Evidence  []Evidence `json:"evidence"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
}

func New(iface, mac string, now time.Time) Device {
	return Device{Interface: iface, MAC: mac, Addresses: []Address{}, Evidence: []Evidence{}, FirstSeen: now, LastSeen: now}
}
