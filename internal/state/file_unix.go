//go:build !windows

package state

import (
	"errors"
	"os"
)

func privateFile(f *os.File) error {
	i, err := f.Stat()
	if err != nil {
		return err
	}
	if i.Mode().Perm()&0077 != 0 {
		return errors.New("state must be a private regular file (0600)")
	}
	return nil
}

func makePrivate(*os.File) error { return nil } // CreateTemp uses 0600.

func replaceFile(from, to string) error { return os.Rename(from, to) }

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
