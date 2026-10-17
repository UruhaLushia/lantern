//go:build !windows

package dhcpserver

import "net"

func sendReplyFrame(s *Service, frame []byte, mac net.HardwareAddr) error {
	return s.observer.Send(frame, mac)
}
