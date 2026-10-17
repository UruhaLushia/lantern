package wininject

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
)

// These tests only publish/read ordinary files in temporary directories. They
// never call Open, load the DLL, or touch any driver/service/network setting.
func bundleTestRoot(t *testing.T) string {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skip("bundle is Windows amd64 only")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating the admin-owned cache requires elevation")
	}
	return filepath.Join(t.TempDir(), "cache")
}

func TestBundlePrepareReuseAndLocks(t *testing.T) {
	root := bundleTestRoot(t)
	b, err := prepareBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	assets, err := embeddedAssets()
	if err != nil {
		t.Fatal(err)
	}
	for _, asset := range assets {
		path := filepath.Join(b.directory, asset.name)
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, asset.data) {
			t.Fatalf("extracted %s: %v", asset.name, err)
		}
		if err := os.WriteFile(path, asset.data, 0600); err == nil {
			t.Fatalf("active bundle file %s allowed writes", asset.name)
		}
		if err := os.Remove(path); err == nil {
			t.Fatalf("active bundle file %s allowed deletion", asset.name)
		}
	}
	if err := os.Rename(root, root+"-moved"); err == nil {
		t.Fatal("active bundle root allowed rename")
	}
	second, err := prepareBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBundleConcurrentPublication(t *testing.T) {
	root := bundleTestRoot(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			b, err := prepareBundle(root)
			if err != nil {
				t.Error(err)
				return
			}
			if err := b.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	paths, err := filepath.Glob(filepath.Join(root, bundleVersion, ".windivert-*"))
	if err != nil || len(paths) != 0 {
		t.Fatalf("leftover temporary files: %v, %v", paths, err)
	}
}

func TestBundleCorruptionIsRejectedWithoutRepair(t *testing.T) {
	root := bundleTestRoot(t)
	b, err := prepareBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(b.directory, "WinDivert64.sys")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1 // Same length, different hash.
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if other, err := prepareBundle(root); err == nil {
		other.Close()
		t.Fatal("corrupted driver accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("damaged file was replaced: %v", err)
	}
	// A rejected preparation must release both file and directory locks.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	other, err := prepareBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
}

func TestBundleRejectsUntrustedDirectory(t *testing.T) {
	root := bundleTestRoot(t)
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if b, err := prepareBundle(root); err == nil {
		b.Close()
		t.Fatal("directory with inherited user-writable ACL accepted")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("untrusted directory was populated: %v", err)
	}
}
