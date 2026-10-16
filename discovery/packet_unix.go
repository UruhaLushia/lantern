//go:build linux || darwin

package discovery

import (
	"context"
	"errors"
	"net"
	"slices"
	"time"

	"github.com/UruhaLushia/lantern/device"
	"github.com/UruhaLushia/lantern/internal/ether"
	"github.com/mdlayher/packet"
)

func Start(ctx context.Context, iface net.Interface, opts Options, store *device.Store) (*Service, error) {
	c, err := ether.Listen(&iface)
	if err != nil {
		return nil, err
	}
	groups := []string{"33:33:00:00:00:01", "33:33:00:00:00:02"}
	if opts.MDNS {
		groups = append(groups, "01:00:5e:00:00:fb", "33:33:00:00:00:fb")
	}
	if opts.SSDP {
		groups = append(groups, "01:00:5e:7f:ff:fa", "33:33:00:00:00:0c")
	}
	for _, group := range groups {
		mac, _ := net.ParseMAC(group)
		if err := c.JoinGroup(mac); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	if opts.AddressTTL <= 0 {
		opts.AddressTTL = 10 * time.Minute
	}
	if opts.DeviceTTL <= 0 {
		opts.DeviceTTL = 24 * time.Hour
	}
	s := &Service{iface: iface, opts: opts, store: store, conn: c, cancel: cancel, done: make(chan struct{}), status: Status{Running: true, Routers: []Router{}, DHCPServers: []DHCPServer{}}}
	go s.loop(ctx)
	return s, nil
}

func (s *Service) loop(ctx context.Context) {
	defer close(s.done)
	defer func() { s.mu.Lock(); s.status.Running = false; s.mu.Unlock() }()
	buf := make([]byte, 4096)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := s.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			s.mu.Lock()
			s.status.Problems = []string{err.Error()}
			s.mu.Unlock()
			return
		}
		f, err := ether.Parse(buf[:n])
		if err != nil {
			continue
		}
		if slices.Equal(f.SourceMAC, s.iface.HardwareAddr) {
			continue
		}
		s.mu.Lock()
		s.status.Frames++
		s.mu.Unlock()
		s.process(f)
	}
}

func (s *Service) Send(frame []byte, destination net.HardwareAddr) error {
	_, err := s.conn.WriteTo(frame, &packet.Addr{HardwareAddr: destination})
	return err
}
