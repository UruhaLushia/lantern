package wininject

import (
	"testing"
	"unsafe"
)

func TestAddressMatchesWinDivert2ABI(t *testing.T) {
	var address Address
	// WinDivert 2.2.2 windivert.h: INT64 timestamp, two UINT32 words,
	// and a 64-byte union. Check the actual compiled layout without a driver.
	if unsafe.Sizeof(address) != 80 || unsafe.Offsetof(address.Timestamp) != 0 ||
		unsafe.Offsetof(address.Flags) != 8 || unsafe.Offsetof(address.Reserved) != 12 || unsafe.Offsetof(address.Data) != 16 {
		t.Fatalf("unexpected WINDIVERT_ADDRESS layout: size=%d flags=%d reserved=%d data=%d",
			unsafe.Sizeof(address), unsafe.Offsetof(address.Flags), unsafe.Offsetof(address.Reserved), unsafe.Offsetof(address.Data))
	}
}
