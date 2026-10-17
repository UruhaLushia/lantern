//go:build !windows

package lantern

import (
	"context"
	"net"
	"runtime"

	"github.com/UruhaLushia/lantern/device"
	"github.com/UruhaLushia/lantern/discovery"
	"github.com/UruhaLushia/lantern/network"
)

func startPlatformDatapath(network.Selection, Options) (platformDatapath, error) { return nil, nil }

func startPlatformDiscovery(ctx context.Context, iface net.Interface, opts discovery.Options, store *device.Store, _ platformDatapath) (*discovery.Service, error) {
	return discovery.Start(ctx, iface, opts, store)
}

func validatePlatform(Options) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return ErrUnsupportedPlatform
	}
	return nil
}
