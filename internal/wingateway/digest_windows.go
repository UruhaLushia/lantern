package wingateway

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

func packetDigest(p []byte) [32]byte {
	if len(p) < 20 {
		return sha256.Sum256(p)
	}
	n := int(binary.BigEndian.Uint16(p[2:4]))
	if n >= 20 && n <= len(p) {
		p = p[:n]
	}
	// Hash checksum fields as zero without copying or mutating the packet.
	transportChecksum := -1
	h := int(p[0]&15) * 4
	if h >= 20 && h <= len(p) && binary.BigEndian.Uint16(p[6:8])&0x3fff == 0 {
		if p[9] == 6 && len(p)-h >= 20 {
			transportChecksum = h + 16
		}
		if p[9] == 17 && len(p)-h >= 8 {
			transportChecksum = h + 6
		}
		if p[9] == 1 && len(p)-h >= 4 {
			transportChecksum = h + 2
		}
	}
	var zero [2]byte
	hash := sha256.New()
	hash.Write(p[:10])
	hash.Write(zero[:])
	if transportChecksum >= 0 {
		hash.Write(p[12:transportChecksum])
		hash.Write(zero[:])
		hash.Write(p[transportChecksum+2:])
	} else {
		hash.Write(p[12:])
	}
	var digest [32]byte
	hash.Sum(digest[:0])
	return digest
}

// Bound self-recapture memory independently of gateway uptime. Original client
// retransmissions retain their original TTL and therefore a different digest.
type recentPackets struct {
	seen    map[[32]byte]packetStamp
	ring    []recentPacket
	next    uint64
	started time.Time
}

type packetStamp struct {
	seq  uint64
	tick int64
}

type recentPacket struct {
	key [32]byte
	seq uint64
}

func newRecentPackets() *recentPackets {
	return &recentPackets{seen: make(map[[32]byte]packetStamp, 65536), ring: make([]recentPacket, 65536), started: time.Now()}
}

func (r *recentPackets) contains(p []byte) bool {
	key := packetDigest(p)
	stamp, ok := r.seen[key]
	if ok && time.Since(r.started).Nanoseconds()-stamp.tick > int64(2*time.Second) {
		delete(r.seen, key)
		return false
	}
	return ok
}

func (r *recentPackets) add(p []byte) {
	i := r.next % uint64(len(r.ring))
	previous := r.ring[i]
	if stamp, found := r.seen[previous.key]; found && stamp.seq == previous.seq {
		delete(r.seen, previous.key)
	}
	r.next++
	entry := recentPacket{packetDigest(p), r.next}
	r.ring[i], r.seen[entry.key] = entry, packetStamp{entry.seq, time.Since(r.started).Nanoseconds()}
}
