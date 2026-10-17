package wininject

// Address has the WinDivert 2.x ABI for NETWORK outbound injection.
type Address struct {
	Timestamp       int64
	Flags, Reserved uint32
	Data            [64]byte
}
