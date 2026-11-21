package probe

import (
	"sort"
)

// groupPaths merges flows that took the same device sequence.  A "path" in
// the output is one distinct route through the network, not one probe flow;
// its weight is the number of flows that took it, and its RTT is the median
// over those flows.  This is what makes a diamond read as two paths rather
// than forty.
func (p *prober) groupPaths() {
	type item struct {
		seq   []string
		rtts  []float64
		key   string
		flows int
	}
	byKey := map[string]*item{}
	var order []string
	for _, pa := range p.paths {
		var devs []string
		var rtts []float64
		prev := ""
		for ttl := 1; ttl < len(pa.Hops); ttl++ {
			a := pa.Hops[ttl]
			if a == "" {
				if prev != "?" {
					devs = append(devs, "?")
					rtts = append(rtts, 0)
					prev = "?"
				}
				continue
			}
			d := p.deviceOf(a)
			if d == prev {
				// Same device seen at two TTLs: one hop whose TTL handling is
				// non-standard, not two devices in a row.
				continue
			}
			devs = append(devs, d)
			rtts = append(rtts, pa.RTT[ttl])
			prev = d
		}
		// Trim trailing unknowns.
		for len(devs) > 0 && devs[len(devs)-1] == "?" {
			devs = devs[:len(devs)-1]
			rtts = rtts[:len(rtts)-1]
		}
		key := ""
		for _, d := range devs {
			key += d + ">"
		}
		it := byKey[key]
		if it == nil {
			it = &item{seq: devs, key: key}
			byKey[key] = it
			order = append(order, key)
		}
		it.flows++
		if len(it.rtts) == 0 {
			it.rtts = make([]float64, len(rtts))
		}
		for i, v := range rtts {
			if v > 0 && (it.rtts[i] == 0 || v < it.rtts[i]) {
				it.rtts[i] = v
			}
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return byKey[order[i]].flows > byKey[order[j]].flows })
	out := make([]Path, 0, len(order))
	for i, k := range order {
		it := byKey[k]
		pa := Path{ID: i, FlowKey: k, Weight: it.flows}
		pa.Hops = append([]string{""}, it.seq...)
		pa.RTT = append([]float64{0}, it.rtts...)
		out = append(out, pa)
	}
	p.mergedGroups = out
}
