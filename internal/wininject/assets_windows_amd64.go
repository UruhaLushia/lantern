package wininject

import "embed"

// Keep the binary pair, notices and corresponding source together in every
// executable that uses the bundled DLL. Other architectures embed no drivers.
//
//go:embed bundle/WinDivert.dll bundle/WinDivert64.sys bundle/LICENSE bundle/NOTICE bundle/WinDivert-2.2.2-source.zip
var bundledFiles embed.FS

func embeddedAssets() ([]bundleAsset, error) {
	var assets []bundleAsset
	for _, name := range []string{"WinDivert.dll", "WinDivert64.sys", "LICENSE", "NOTICE", "WinDivert-2.2.2-source.zip"} {
		data, err := bundledFiles.ReadFile("bundle/" + name)
		if err != nil {
			return nil, err
		}
		assets = append(assets, bundleAsset{name: name, data: data})
	}
	return assets, nil
}
