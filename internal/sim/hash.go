package sim

import "encoding/binary"

const (
	fnvOffset64 = 14695981039346656037
	fnvPrime64  = 1099511628211
)

func fnvInit() uint64 { return fnvOffset64 }

func fnvAddU64(h uint64, v uint64) uint64 {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	for _, c := range b {
		h ^= uint64(c)
		h *= fnvPrime64
	}
	return h
}

func fnvAddStr(h uint64, s string) uint64 {
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= fnvPrime64
	}
	return h
}

func fnvAddAddr(h uint64, a interface{ String() string }) uint64 {
	return fnvAddStr(h, a.String())
}

func fnvAddField(h uint64, f HashField, p Probe) uint64 {
	switch f {
	case FieldSrcIP:
		return fnvAddStr(h, p.SrcIP)
	case FieldDstIP:
		return fnvAddStr(h, p.DstIP)
	case FieldSrcPort:
		return fnvAddU64(h, uint64(p.SrcPort))
	case FieldDstPort:
		return fnvAddU64(h, uint64(p.DstPort))
	case FieldProto:
		return fnvAddU64(h, uint64(p.Proto))
	case FieldTOS:
		return fnvAddU64(h, uint64(p.TOS))
	case FieldIPID:
		return fnvAddU64(h, uint64(p.IPID))
	case FieldFlowLabel:
		return fnvAddU64(h, uint64(p.FlowLabel))
	}
	return h
}
