//go:build windows && !amd64

package wininject

import "errors"

func embeddedAssets() ([]bundleAsset, error) {
	return nil, errors.New("bundled WinDivert requires Windows amd64")
}
