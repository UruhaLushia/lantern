package wininject

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const bundleVersion = "2.2.2-A-amd64"

// The owner and all writers must be administrators or SYSTEM. Read/execute
// access permits reuse without granting ordinary users replacement rights.
const bundleSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"

type bundleAsset struct {
	name string
	data []byte
}

type driverBundle struct {
	directory string
	files     []*os.File
}

func (b *driverBundle) Close() error {
	if b == nil {
		return nil
	}
	var err error
	for len(b.files) > 0 {
		i := len(b.files) - 1
		err = errors.Join(err, b.files[i].Close())
		b.files = b.files[:i]
	}
	return err
}

func openEmbeddedBundle() (*driverBundle, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return nil, err
	}
	return prepareBundle(filepath.Join(base, "Lantern-WinDivert"))
}

// prepareBundle writes no services or registry settings and loads no DLLs.
// Publish complete files without replacement, then pin their contents against
// writes/deletion until the sender has closed. Never hot-repair a shared cache.
func prepareBundle(root string) (_ *driverBundle, err error) {
	assets, err := embeddedAssets()
	if err != nil {
		return nil, err
	}
	b := &driverBundle{directory: filepath.Join(root, bundleVersion)}
	defer func() {
		if err != nil {
			err = errors.Join(err, b.Close())
		}
	}()
	for _, path := range []string{root, b.directory} {
		f, openErr := openBundleDirectory(path)
		if openErr != nil {
			return nil, fmt.Errorf("prepare WinDivert directory %s (first use requires elevation): %w", path, openErr)
		}
		b.files = append(b.files, f)
	}
	for _, asset := range assets {
		path := filepath.Join(b.directory, asset.name)
		if err := publishAsset(path, asset.data); err != nil {
			return nil, err
		}
		f, err := lockBundleFile(path, asset.data)
		if err != nil {
			return nil, err
		}
		b.files = append(b.files, f)
	}
	return b, nil
}

func openBundleDirectory(path string) (*os.File, error) {
	sd, err := windows.SecurityDescriptorFromString(bundleSDDL)
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	err = windows.CreateDirectory(p, &sa)
	runtime.KeepAlive(sd)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	if err := checkBundleDirectory(h); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func checkBundleDirectory(h windows.Handle) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("bundle directory must be a plain directory, not a reparse point")
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	// Compare only the owner and DACL, which were requested above. Fail closed
	// for pre-existing directories with a different policy; never take them over.
	expected, err := windows.SecurityDescriptorFromString(bundleSDDL)
	if err != nil {
		return err
	}
	if sd.String() != expected.String() {
		return fmt.Errorf("unsafe WinDivert directory permissions: %s", sd.String())
	}
	return nil
}

func publishAsset(path string, data []byte) error {
	if _, err := os.Lstat(path); err == nil {
		return nil // Validate the existing file while locked, never replace it.
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".windivert-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// Without REPLACE_EXISTING only one concurrent publisher wins. The caller
	// validates the winner's bytes, including when another process won the race.
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		if _, statErr := os.Lstat(path); statErr != nil {
			return errors.Join(err, statErr)
		}
	}
	return nil
}

func lockBundleFile(path string, expected []byte) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	var info windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(h, &info)
	if err == nil && (info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 ||
		info.FileSizeHigh != 0 || int64(info.FileSizeLow) != int64(len(expected))) {
		err = errors.New("unexpected file type or size")
	}
	if err == nil {
		hash := sha256.New()
		_, err = io.Copy(hash, io.LimitReader(f, int64(len(expected))+1))
		want := sha256.Sum256(expected)
		if err == nil && !bytes.Equal(hash.Sum(nil), want[:]) {
			err = errors.New("SHA256 mismatch")
		}
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("bundled WinDivert file %s: %w; cache left unchanged", path, err), f.Close())
	}
	return f, nil
}
