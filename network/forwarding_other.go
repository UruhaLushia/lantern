//go:build !linux

package network

import "errors"

func ForwardingReady(string, bool, bool) error {
	return errors.New("forwarding readiness currently requires Linux")
}
