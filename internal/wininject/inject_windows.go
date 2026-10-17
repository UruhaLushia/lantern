// Package wininject sends IPv4 packets through WinDivert. The caller
// must explicitly authorize loading a driver; the default forbids installation.
package wininject

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Sender struct {
	mu                     sync.Mutex
	dll                    *windows.DLL
	bundle                 *driverBundle
	handle                 uintptr
	send, checksums, close *windows.Proc
	sendEx                 *windows.Proc
	batch                  []byte
	batchAddresses         [maxBatchPackets]Address
}

// Open uses the bundled, verified DLL when directory is empty. An explicit
// directory selects the caller's library (including compatible modifications).
// Neither mode permits driver installation unless allowDriverLoad is true.
func Open(directory string, allowDriverLoad bool) (_ *Sender, err error) {
	if runtime.GOARCH != "amd64" {
		return nil, errors.New("WinDivert injection requires Windows amd64")
	}
	var bundle *driverBundle
	if directory == "" {
		bundle, err = openEmbeddedBundle()
		if err != nil {
			return nil, err
		}
		directory = bundle.directory
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, bundle.Close())
		}
	}()
	path, err := filepath.Abs(filepath.Join(directory, "WinDivert.dll"))
	if err != nil {
		return nil, err
	}
	h, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, err
	}
	dll := &windows.DLL{Name: path, Handle: h}
	failed := true
	defer func() {
		if failed {
			_ = dll.Release()
		}
	}()
	open, err := dll.FindProc("WinDivertOpen")
	if err != nil {
		return nil, err
	}
	s := &Sender{dll: dll, bundle: bundle}
	s.send, err = dll.FindProc("WinDivertSend")
	if err != nil {
		return nil, err
	}
	s.sendEx, err = dll.FindProc("WinDivertSendEx")
	if err != nil {
		return nil, err
	}
	s.checksums, err = dll.FindProc("WinDivertHelperCalcChecksums")
	if err != nil {
		return nil, err
	}
	s.close, err = dll.FindProc("WinDivertClose")
	if err != nil {
		return nil, err
	}
	filter, _ := windows.BytePtrFromString("false")
	flags := uintptr(0x0008) // SEND_ONLY: installs no packet capture/drop filter.
	if !allowDriverLoad {
		flags |= 0x0010
	} // NO_INSTALL.
	// Windows routes NETWORK layer outbound packets. IfIdx cannot force
	// an outbound packet into a TUN; the caller must verify its route.
	value, _, err := open.Call(uintptr(unsafe.Pointer(filter)), 0, 0, flags)
	if value == uintptr(windows.InvalidHandle) {
		return nil, fmt.Errorf("WinDivertOpen (driver load allowed=%t): %w", allowDriverLoad, err)
	}
	s.handle = value
	failed = false
	return s, nil
}

func (s *Sender) Send(packet []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == 0 {
		return net.ErrClosed
	}
	if _, err := batchSize([][]byte{packet}); err != nil {
		return err
	}
	a := Address{Flags: 1 << 17} // Outbound at NETWORK layer.
	ok, _, err := s.checksums.Call(uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)), uintptr(unsafe.Pointer(&a)), 0)
	if ok == 0 {
		return fmt.Errorf("WinDivertHelperCalcChecksums: %w", err)
	}
	var sent uint32
	ok, _, err = s.send.Call(s.handle, uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)), uintptr(unsafe.Pointer(&sent)), uintptr(unsafe.Pointer(&a)))
	if ok == 0 {
		return fmt.Errorf("WinDivertSend: %w", err)
	}
	if sent != uint32(len(packet)) {
		return errors.New("short WinDivert injection")
	}
	return nil
}

func (s *Sender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle != 0 {
		ok, _, err := s.close.Call(s.handle)
		if ok == 0 {
			return fmt.Errorf("WinDivertClose; DLL retained: %w", err)
		}
		s.handle = 0
	}
	if s.dll == nil {
		return nil
	}
	if err := s.dll.Release(); err != nil {
		return err
	}
	s.dll = nil
	return s.bundle.Close()
}
