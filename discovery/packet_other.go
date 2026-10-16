//go:build !linux && !darwin

package discovery

import (
	"context"
	"errors"
	"net"

	"github.com/UruhaLushia/lantern/device"
)

func Start(context.Context, net.Interface, Options, *device.Store) (*Service, error) {
	return nil, errors.New("packet discovery requires Linux or macOS")
}
func (*Service) Send([]byte, net.HardwareAddr) error {
	return errors.New("packet transmission requires Linux or macOS")
}
