package wingateway

import (
	"errors"
	"net/netip"
	"time"
)

type sourceSet map[netip.Addr]time.Time

type binding struct {
	ip      netip.Addr
	expires time.Time
}

// setClients initializes the static sources without installing routes.
func (s *Service) setClients(clients []netip.Addr) error {
	if len(clients) > 65536 {
		return errors.New("too many IPv4 clients")
	}
	sources := make(sourceSet, len(clients))
	for _, client := range clients {
		if err := validateClient(s.lan, client); err != nil {
			return err
		}
		sources[client] = time.Time{}
	}
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	s.manual = sources
	s.publishSourcesLocked()
	return nil
}

// SetLease prepares/revokes one DHCP binding before ACK. Expired bindings are
// excluded on every packet, independently of the controller's poll interval.
func (s *Service) SetLease(mac string, ip netip.Addr, expires time.Time, selected bool) error {
	if err := s.Ready(); err != nil {
		return err
	}
	if selected && expires.After(time.Now()) {
		if err := validateClient(s.lan, ip); err != nil {
			return err
		}
	}
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	if !selected || !expires.After(time.Now()) {
		delete(s.bindings, mac)
	} else {
		if len(s.bindings) >= 65536 {
			if _, exists := s.bindings[mac]; !exists {
				return errors.New("too many DHCP gateway bindings")
			}
		}
		s.bindings[mac] = binding{ip, expires}
	}
	s.publishSourcesLocked()
	return nil
}

func (s *Service) ClearLeases() {
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	clear(s.bindings)
	s.publishSourcesLocked()
}

func (s *Service) publishSourcesLocked() {
	sources := make(sourceSet, len(s.manual)+len(s.bindings))
	for ip, until := range s.manual {
		sources[ip] = until
	}
	for mac, b := range s.bindings {
		if !b.expires.After(time.Now()) {
			delete(s.bindings, mac)
			continue
		}
		if _, manual := s.manual[b.ip]; !manual {
			sources[b.ip] = b.expires
		}
	}
	s.sources.Store(&sources)
}
