//go:build !linux && !darwin

package network

import "errors"

func ForwardingReady(string, bool, bool) error {
	return errors.New("forwarding readiness requires Linux or macOS")
}
