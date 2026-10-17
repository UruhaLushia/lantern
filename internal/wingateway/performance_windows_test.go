package wingateway

import (
	"fmt"
	"testing"
)

// This measures only user-space packet work, with no sockets or driver calls.
// It deliberately excludes route guards and injection latency.
func BenchmarkNativePacketPipeline(b *testing.B) {
	for _, size := range []int{64, 512, 1500} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			client := testClientIP()
			packet := testUDPPacket(b, client, make([]byte, size-28))
			storage := make([]byte, 0, 65535)
			b.ReportAllocs()
			b.SetBytes(int64(len(packet)))
			b.ResetTimer()
			for b.Loop() {
				before := packetDigest(packet)
				prepared, err := prepareIPv4Into(storage, packet, client)
				if err != nil {
					b.Fatal(err)
				}
				storage = prepared[:0]
				if before == packetDigest(prepared) {
					b.Fatal("TTL change lost in fingerprint")
				}
			}
		})
	}
}
