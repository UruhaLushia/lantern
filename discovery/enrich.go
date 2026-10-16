package discovery

import (
	"bufio"
	"bytes"
	"net/netip"
	"net/textproto"
	"strings"

	"github.com/UruhaLushia/lantern/device"
	"github.com/UruhaLushia/lantern/internal/ether"
	"golang.org/x/net/dns/dnsmessage"
)

func (s *Service) mdns(f ether.Frame, d ether.Datagram) {
	if d.HopLimit != 255 || len(d.Payload) > 2048 {
		return
	}
	var m dnsmessage.Message
	if err := m.Unpack(d.Payload); err != nil {
		s.malformed()
		return
	}
	if !m.Response {
		return
	}
	records := append(append(m.Answers, m.Additionals...), m.Authorities...)
	if len(records) > 128 {
		return
	}
	var e []device.Evidence
	for _, r := range records {
		switch b := r.Body.(type) {
		case *dnsmessage.AResource:
			if netip.AddrFrom4(b.A) == d.Source {
				e = append(e, device.Evidence{Field: "hostname", Value: strings.TrimSuffix(r.Header.Name.String(), ".")})
			}
		case *dnsmessage.AAAAResource:
			if netip.AddrFrom16(b.AAAA) == d.Source {
				e = append(e, device.Evidence{Field: "hostname", Value: strings.TrimSuffix(r.Header.Name.String(), ".")})
			}
		case *dnsmessage.PTRResource:
			e = append(e, device.Evidence{Field: "service", Value: b.PTR.String()})
			if strings.Contains(b.PTR.String(), "_airplay.") {
				e = append(e, device.Evidence{Field: "manufacturer", Value: "Apple-compatible", Confidence: device.Inferred})
			}
		case *dnsmessage.TXTResource:
			for _, txt := range b.TXT {
				parts := strings.SplitN(txt, "=", 2)
				if len(parts) != 2 {
					continue
				}
				switch strings.ToLower(parts[0]) {
				case "model", "manufacturer", "fn":
					e = append(e, device.Evidence{Field: "advertised_" + strings.ToLower(parts[0]), Value: parts[1]})
				}
			}
		}
	}
	s.observe(f.SourceMAC, d.Source, "mdns", e...)
	s.mu.Lock()
	s.status.MDNSPackets++
	s.mu.Unlock()
}

func (s *Service) ssdp(f ether.Frame, d ether.Datagram) {
	if len(d.Payload) > 2048 {
		return
	}
	r := textproto.NewReader(bufio.NewReader(bytes.NewReader(d.Payload)))
	line, err := r.ReadLine()
	if err != nil || (!strings.HasPrefix(line, "HTTP/1.1 200") && !strings.HasPrefix(line, "NOTIFY * HTTP/1.1")) {
		return
	}
	h, err := r.ReadMIMEHeader()
	if err != nil {
		s.malformed()
		return
	}
	var e []device.Evidence
	for _, field := range []string{"Server", "Usn", "St", "Nt", "Location"} {
		if v := h.Get(field); v != "" {
			e = append(e, device.Evidence{Field: "ssdp_" + strings.ToLower(field), Value: v})
		}
	}
	server := strings.ToLower(h.Get("Server"))
	for _, os := range []string{"android", "windows", "linux", "ios"} {
		if strings.Contains(server, os) {
			e = append(e, device.Evidence{Field: "os", Value: os, Confidence: device.Inferred})
			break
		}
	}
	s.observe(f.SourceMAC, d.Source, "ssdp", e...)
	s.mu.Lock()
	s.status.SSDPPackets++
	s.mu.Unlock()
}
