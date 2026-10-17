package wincapture

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestReadPacketRejectsBeforeNativeReceive(t *testing.T) {
	socket := &Socket{}
	if _, err := socket.ReadPacket(make([]byte, 65535)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed receive: %v", err)
	}
	// No real socket or native receive: a short buffer is rejected first.
	socket.open = true
	if _, err := socket.ReadPacket(make([]byte, 1500)); err == nil {
		t.Fatal("accepted buffer that could truncate an IPv4 packet")
	}
}

func TestLiveAvailableRead(t *testing.T) {
	text := os.Getenv("LANTERN_TEST_CAPTURE_IPV4")
	if text == "" {
		t.Skip("requires explicit existing LAN IPv4; native receive only, no injection")
	}
	local, err := netip.ParseAddr(text)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := Open(local)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := socket.Close(); err != nil {
			t.Error(err)
		}
	}()
	buffer := make([]byte, 65535)
	started := time.Now()
	for range 32 {
		n, err := socket.ReadAvailablePacket(buffer)
		if err != nil || (n != 0 && (n < 20 || buffer[0]>>4 != 4)) {
			t.Fatalf("available read: %d, %v", n, err)
		}
	}
	if time.Since(started) > time.Second {
		t.Fatal("available receive calls unexpectedly waited")
	}
}
