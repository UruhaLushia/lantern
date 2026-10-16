package ether

import (
	"fmt"

	"golang.org/x/net/bpf"
)

func ControlFilter() ([]bpf.RawInstruction, error) {
	type branch struct {
		at      int
		yes, no string
	}
	var ins []bpf.Instruction
	labels := map[string]int{}
	var branches []branch
	label := func(s string) { labels[s] = len(ins) }
	load := func(off int, size int) { ins = append(ins, bpf.LoadAbsolute{Off: uint32(off), Size: size}) }
	jump := func(cond bpf.JumpTest, v uint32, yes, no string) {
		branches = append(branches, branch{len(ins), yes, no})
		ins = append(ins, bpf.JumpIf{Cond: cond, Val: v})
	}
	label("ether")
	load(12, 2)
	jump(bpf.JumpEqual, 0x806, "accept", "v4")
	label("v4")
	jump(bpf.JumpEqual, 0x800, "ip4", "v6")
	label("v6")
	jump(bpf.JumpEqual, 0x86dd, "ip6", "vlan")
	label("vlan")
	jump(bpf.JumpEqual, 0x8100, "accept", "qinq")
	label("qinq")
	jump(bpf.JumpEqual, 0x88a8, "accept", "reject")
	label("ip4")
	load(23, 1)
	jump(bpf.JumpEqual, 17, "frag", "reject")
	label("frag")
	load(20, 2)
	jump(bpf.JumpBitsSet, 0x3fff, "reject", "ihl")
	label("ihl")
	ins = append(ins, bpf.LoadMemShift{Off: 14}, bpf.LoadIndirect{Off: 14, Size: 2})
	for i, p := range []uint32{67, 68, 5353, 1900} {
		label(fmt.Sprintf("s4%d", i))
		next := fmt.Sprintf("s4%d", i+1)
		if i == 3 {
			next = "d4"
		}
		jump(bpf.JumpEqual, p, "accept", next)
	}
	label("d4")
	ins = append(ins, bpf.LoadIndirect{Off: 16, Size: 2})
	for i, p := range []uint32{67, 68, 5353, 1900} {
		label(fmt.Sprintf("d4%d", i))
		next := fmt.Sprintf("d4%d", i+1)
		if i == 3 {
			next = "reject"
		}
		jump(bpf.JumpEqual, p, "accept", next)
	}
	label("ip6")
	load(20, 1)
	jump(bpf.JumpEqual, 58, "accept", "udp6")
	label("udp6")
	jump(bpf.JumpEqual, 17, "ports6", "hop6")
	label("hop6")
	jump(bpf.JumpEqual, 0, "accept", "dest6")
	label("dest6")
	jump(bpf.JumpEqual, 60, "accept", "reject")
	label("ports6")
	load(54, 2)
	jump(bpf.JumpEqual, 5353, "accept", "ssdp6")
	label("ssdp6")
	jump(bpf.JumpEqual, 1900, "accept", "d6")
	label("d6")
	load(56, 2)
	jump(bpf.JumpEqual, 5353, "accept", "ds6")
	label("ds6")
	jump(bpf.JumpEqual, 1900, "accept", "reject")
	label("accept")
	ins = append(ins, bpf.RetConstant{Val: 2048})
	label("reject")
	ins = append(ins, bpf.RetConstant{Val: 0})
	for _, b := range branches {
		j := ins[b.at].(bpf.JumpIf)
		y, n := labels[b.yes]-b.at-1, labels[b.no]-b.at-1
		if y < 0 || y > 255 || n < 0 || n > 255 {
			return nil, fmt.Errorf("invalid filter jump")
		}
		j.SkipTrue, j.SkipFalse = uint8(y), uint8(n)
		ins[b.at] = j
	}
	return bpf.Assemble(ins)
}
