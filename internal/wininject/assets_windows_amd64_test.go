package wininject

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"fmt"
	"testing"
)

func TestBundledReleaseIntegrity(t *testing.T) {
	assets, err := embeddedAssets()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"WinDivert.dll":              "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2",
		"WinDivert64.sys":            "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2",
		"LICENSE":                    "14a0cb5214d536e4fdae6aa3f5696f981eeda106cd026e9794bba489ee79d628",
		"WinDivert-2.2.2-source.zip": "65ec79c9e6afa99f648a3f4d1f6db794640b40d0b65bd438770ea503ee14ecb7",
	}
	for _, asset := range assets {
		if hash, pinned := want[asset.name]; pinned {
			if got := fmt.Sprintf("%x", sha256.Sum256(asset.data)); got != hash {
				t.Fatalf("%s differs from reviewed upstream release: %s", asset.name, got)
			}
			delete(want, asset.name)
		}
		if asset.name == "WinDivert.dll" || asset.name == "WinDivert64.sys" {
			image, err := pe.NewFile(bytes.NewReader(asset.data))
			if err != nil {
				t.Fatal(err)
			}
			if image.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
				t.Fatalf("wrong PE machine for %s: %x", asset.name, image.Machine)
			}
			image.Close()
		}
		if asset.name == "WinDivert-2.2.2-source.zip" {
			archive, err := zip.NewReader(bytes.NewReader(asset.data), int64(len(asset.data)))
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"dll/windivert.c", "sys/windivert.c", "include/windivert.h", "mingw-build.sh", "msvc-build.bat", "release-build.sh", "LICENSE"} {
				f, err := archive.Open("WinDivert-2.2.2/" + path)
				if err != nil {
					t.Fatalf("corresponding source missing %s: %v", path, err)
				}
				f.Close()
			}
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing release assets: %v", want)
	}
}
