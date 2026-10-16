//go:build !linux

package discovery

import (
	"context"
	"errors"
	"net"

	"github.com/UruhaLushia/lantern/device"
)

func Start(context.Context, net.Interface, Options, *device.Store) (*Service, error) {
	return nil, errors.New("packet discovery currently requires Linux")
}
func (*Service) Send([]byte, net.HardwareAddr) error {
	return errors.New("packet transmission currently requires Linux")
}
