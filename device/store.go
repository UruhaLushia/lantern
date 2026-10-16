package device

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

type Observation struct {
	Interface string
	MAC       net.HardwareAddr
	IP        netip.Addr
	Source    string
	Evidence  []Evidence
	At        time.Time
	TTL       time.Duration
}

type Store struct {
	mu      sync.RWMutex
	devices map[string]Device
	limit   int
}

func NewStore(limit int) *Store {
	if limit <= 0 {
		limit = 4096
	}
	return &Store{devices: make(map[string]Device), limit: limit}
}

func Key(iface, mac string) string { return iface + "/" + strings.ToLower(mac) }

func (s *Store) Observe(o Observation) error {
	if o.Interface == "" || len(o.MAC) != 6 || o.MAC[0]&1 != 0 || slices.Equal(o.MAC, make([]byte, 6)) {
		return errors.New("observation needs an interface and unicast Ethernet MAC")
	}
	if o.At.IsZero() {
		o.At = time.Now().UTC()
	}
	if o.TTL <= 0 {
		o.TTL = 10 * time.Minute
	}
	mac := o.MAC.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	k := Key(o.Interface, mac)
	d, ok := s.devices[k]
	if !ok {
		if len(s.devices) >= s.limit {
			return errors.New("device capacity reached")
		}
		d = New(o.Interface, mac, o.At)
	}
	if o.At.After(d.LastSeen) {
		d.LastSeen = o.At
	}
	ip := o.IP.WithZone("").Unmap()
	if ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback() {
		expires := o.At.Add(o.TTL)
		idx := slices.IndexFunc(d.Addresses, func(a Address) bool { return a.IP == ip })
		if idx >= 0 {
			if o.At.After(d.Addresses[idx].LastSeen) {
				d.Addresses[idx].LastSeen, d.Addresses[idx].Source, d.Addresses[idx].ExpiresAt = o.At, o.Source, &expires
			}
		} else if len(d.Addresses) < 32 {
			d.Addresses = append(d.Addresses, Address{IP: ip, Source: o.Source, FirstSeen: o.At, LastSeen: o.At, ExpiresAt: &expires})
		}
	}
	for _, e := range o.Evidence {
		if e.Field == "" || e.Value == "" {
			continue
		}
		if len(e.Value) > 512 {
			e.Value = e.Value[:512]
		}
		if e.Source == "" {
			e.Source = o.Source
		}
		if e.Confidence == "" {
			e.Confidence = Observed
		}
		if e.ObservedAt.IsZero() {
			e.ObservedAt = o.At
		}
		idx := slices.IndexFunc(d.Evidence, func(v Evidence) bool { return v.Field == e.Field && v.Source == e.Source })
		if idx >= 0 {
			d.Evidence[idx] = e
		} else if len(d.Evidence) < 64 {
			d.Evidence = append(d.Evidence, e)
		}
	}
	s.devices[k] = d
	return nil
}

func (s *Store) Expire(now time.Time, deviceTTL time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, d := range s.devices {
		if deviceTTL > 0 && now.Sub(d.LastSeen) > deviceTTL {
			delete(s.devices, k)
			continue
		}
		d.Addresses = slices.DeleteFunc(d.Addresses, func(a Address) bool { return a.ExpiresAt != nil && !a.ExpiresAt.After(now) })
		s.devices[k] = d
	}
}

func (s *Store) ForgetAddress(iface string, mac net.HardwareAddr, ip netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := Key(iface, mac.String())
	d, ok := s.devices[k]
	if !ok {
		return
	}
	d.Addresses = slices.DeleteFunc(d.Addresses, func(a Address) bool { return a.IP == ip.WithZone("").Unmap() })
	s.devices[k] = d
}

func (s *Store) Snapshot() []Device {
	s.mu.RLock()
	result := make([]Device, 0, len(s.devices))
	for _, d := range s.devices {
		d.Addresses = slices.Clone(d.Addresses)
		for i := range d.Addresses {
			if d.Addresses[i].ExpiresAt != nil {
				t := *d.Addresses[i].ExpiresAt
				d.Addresses[i].ExpiresAt = &t
			}
		}
		d.Evidence = slices.Clone(d.Evidence)
		result = append(result, d)
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		return Key(result[i].Interface, result[i].MAC) < Key(result[j].Interface, result[j].MAC)
	})
	return result
}

func Owners(devices []Device, iface string, ip netip.Addr) []string {
	var owners []string
	ip = ip.WithZone("").Unmap()
	for _, d := range devices {
		if d.Interface != iface {
			continue
		}
		for _, a := range d.Addresses {
			if a.IP == ip {
				owners = append(owners, d.MAC)
				break
			}
		}
	}
	return owners
}
