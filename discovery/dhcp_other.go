//go:build !linux && !darwin

package discovery

import (
	"context"
	"errors"
	"time"
)

func ProbeDHCP(context.Context, string, time.Duration) (DHCPProbe, error) {
	return DHCPProbe{}, errors.New("DHCP probing requires Linux or macOS")
}
