package state

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func stateSecurity() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")")
}

func makePrivate(f *os.File) error {
	sd, err := stateSecurity()
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(f.Name(), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func privateFile(f *os.File) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	expected, err := stateSecurity()
	if err != nil {
		return err
	}
	// Windows may set the informational AUTO_INHERITED bit when applying a
	// protected DACL. It does not change its ACEs or re-enable inheritance.
	if err := sd.SetControl(windows.SE_DACL_AUTO_INHERITED|windows.SE_DACL_AUTO_INHERIT_REQ, 0); err != nil {
		return err
	}
	if sd.String() != expected.String() {
		return fmt.Errorf("state must have a private Windows DACL: got %s, want %s", sd.String(), expected.String())
	}
	return nil
}

func replaceFile(from, to string) error {
	f, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(f, t, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// FlushFileBuffers does not support directory handles on Windows. The file is
// flushed before publication; use a write-through rename for that publication.
func syncDirectory(string) error { return nil }
