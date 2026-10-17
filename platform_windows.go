package lantern

import (
	"context"
	"errors"
	"net"

	"github.com/UruhaLushia/lantern/device"
	"github.com/UruhaLushia/lantern/discovery"
	"github.com/UruhaLushia/lantern/internal/wingateway"
	"github.com/UruhaLushia/lantern/network"
)

type windowsDatapath struct{ *wingateway.Service }

func startPlatformDiscovery(ctx context.Context, iface net.Interface, opts discovery.Options, store *device.Store, datapath platformDatapath) (*discovery.Service, error) {
	if d, ok := datapath.(windowsDatapath); ok {
		return discovery.StartIPv4Observer(ctx, iface, opts, store, d.Service)
	}
	return discovery.Start(ctx, iface, opts, store)
}

func (d windowsDatapath) Snapshot() IPv4GatewayStatus {
	s := d.Service.Snapshot()
	return IPv4GatewayStatus{Running: s.Running, Forwarded: s.Forwarded, SendCalls: s.SendCalls, SelfIgnored: s.SelfIgnored, Dropped: s.Dropped, LastError: s.LastError}
}

func startPlatformDatapath(selected network.Selection, opts Options) (platformDatapath, error) {
	if opts.WindowsGateway == nil {
		return nil, ErrUnsupportedPlatform
	}
	o := opts.WindowsGateway
	s, err := wingateway.Start(context.Background(), wingateway.Options{Interface: selected.Interface.Name, LocalIPv4: o.LocalIPv4.String(), EgressInterface: o.EgressInterface, DriverDirectory: o.DriverDirectory, AllowDriverLoad: o.AllowDriverLoad, Clients: o.Clients, BatchSize: o.BatchSize})
	if err != nil {
		return nil, err
	}
	return windowsDatapath{s}, nil
}

func validatePlatform(opts Options) error {
	if opts.WindowsGateway == nil {
		return ErrUnsupportedPlatform
	}
	if opts.RA.Enabled {
		return errors.New("Windows gateway currently supports IPv4 only; RA must be disabled")
	}
	return nil
}
