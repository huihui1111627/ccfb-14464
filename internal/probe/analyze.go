package probe

import (
	"fmt"
	"sort"

	"topomap/internal/sim"
)

type fstat struct {
	tried, changed int
}

// analyze turns per-hop observations into the public LB findings and lists
// the quirks that make naive traceroute draw false links.
func (p *prober) analyze() {
	p.lb = nil
	maxTTL := 0
	for ttl := range p.hopPkts {
		if ttl > maxTTL {
			maxTTL = ttl
		}
	}
	for ttl := 1; ttl <= maxTTL; ttl++ {
		total := p.hopPkts[ttl]
		if total == 0 {
			continue
		}
		devs := p.hopDevs[ttl]
		if p.hopNone[ttl] == total {
			p.lb = append(p.lb, LBFinding{TTL: ttl, Mode: "silent", Confidence: 0.9,
				Evidence: fmt.Sprintf("no reply to any of %d probes at this TTL", total)})
			continue
		}
		if len(devs) <= 1 {
			// One downstream device along the reference flows.  A policy can
			// still be present: destination-keyed balancing only shows when
			// the destination changes, and packet-keyed balancing only shows
			// when it splays.  Report what was measured rather than assuming
			// "single".
			mode := "single"
			ev := "one downstream device across all flows and destinations tested"
			if p.lbMode[ttl] == "per-destination" {
				mode = "per-destination"
				ev = "one device on these destinations, but the destination prefix selects a different one at this hop"
			}
			var fs []string
			if m := p.hopFields[ttl]; m != nil {
				for _, f := range sim.AllHashFields {
					st := m[f]
					if st != nil && st.tried >= 3 && ratio(st.changed, st.tried) >= 0.25 &&
						binomialConfidence(st.changed, st.tried, 0.05) >= 0.99 {
						fs = append(fs, f.String())
					}
				}
			}
			p.lb = append(p.lb, LBFinding{TTL: ttl, Mode: mode, Branches: 1, Fields: fs, Confidence: 0.8, Evidence: ev})
			continue
		}
		mode := p.lbMode[ttl]
		if mode == "" {
			mode = "per-flow"
		}
		var fs []string
		if m := p.hopFields[ttl]; m != nil {
			for _, f := range sim.AllHashFields {
				st := m[f]
				if st == nil || st.tried < 3 {
					continue
				}
				if ratio(st.changed, st.tried) >= 0.25 && binomialConfidence(st.changed, st.tried, 0.05) >= 0.99 {
					fs = append(fs, f.String())
				}
			}
		}
		conf := 0.85
		ev := fmt.Sprintf("%d devices observed at this hop", len(devs))
		switch mode {
		case "per-packet":
			conf = 0.95
			ev = fmt.Sprintf("identical header tuples split %.0f%% of the time; header fields cannot pin a path here", p.spray[ttl]*100)
		case "per-destination":
			ev = "changing the destination prefix moves the path at this hop"
		case "per-flow":
			ev = fmt.Sprintf("fixed tuples stay put; varying %v moves the path", fs)
		}
		if len(p.hopFields[ttl]) == 0 {
			fs = nil
		}
		p.lb = append(p.lb, LBFinding{
			TTL: ttl, Mode: mode, Branches: len(devs), Fields: fs,
			Confidence: conf, Evidence: ev,
		})
	}
	// Draw the branches from the fused graph so widths and delays are in one
	// place.
}

func maxi(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// anomalies flags the quirks that make naive traceroute lie.
func (p *prober) anomalies() []Anomaly {
	var out []Anomaly
	maxTTL := 0
	for ttl := range p.hopPkts {
		if ttl > maxTTL {
			maxTTL = ttl
		}
	}
	for ttl := 1; ttl < maxTTL; ttl++ {
		tot := p.hopPkts[ttl]
		if tot == 0 {
			continue
		}
		if p.hopNone[ttl] == tot && (p.hopPkts[ttl-1] > p.hopNone[ttl-1] || p.hopPkts[ttl+1] > p.hopNone[ttl+1]) {
			out = append(out, Anomaly{Kind: "silent-hop", TTL: ttl, Confidence: 0.9,
				Detail: fmt.Sprintf("TTL %d never answered while its neighbours did; a naive traceroute silently drops it and splices the two visible hops together", ttl)})
		}
	}
	// Devices answering at two adjacent TTLs are TTL-hiding devices.  Those
	// are routers whose decrement is not 1: they make hop numbers stop
	// matching distances.  A silent router in front of an answering one also
	// shifts the first answering TTL, which is indistinguishable from the
	// outside and reported as the same kind of caveat.
	devTTLs := map[string]map[int]bool{}
	for ttl, m := range p.hopDevs {
		for d := range m {
			if devTTLs[d] == nil {
				devTTLs[d] = map[int]bool{}
			}
			devTTLs[d][ttl] = true
		}
	}
	var hideDevs []string
	for d, ts := range devTTLs {
		if len(ts) > 1 {
			hideDevs = append(hideDevs, d)
			out = append(out, Anomaly{Kind: "ttl-hiding", TTL: minTTL(ts), Devices: []string{d},
				Confidence: 0.85,
				Detail:     fmt.Sprintf("device %s answered at TTLs %v; it decrements TTL by more than one or hides a hop in front of it, so hop counts are not distances", d, sortedInts(ts))})
		}
	}
	for ttl := 1; ttl <= maxTTL; ttl++ {
		tot := p.hopPkts[ttl]
		lost := p.hopNone[ttl]
		if tot >= 12 && lost > 0 && float64(lost)/float64(tot) > 0.2 && len(p.hopDevs[ttl]) > 0 {
			out = append(out, Anomaly{Kind: "rate-limited", TTL: ttl, Confidence: float64(lost) / float64(tot),
				Detail: fmt.Sprintf("hop %d answered %d of %d probes (%.0f%% loss); ICMP rate limiting, not a dead or overloaded router", ttl, tot-lost, tot, 100*float64(lost)/float64(tot))})
		}
	}
	seenOuter := map[int]bool{}
	for _, r := range p.records {
		if r.ReplyKind == "none" || r.OuterTTL == 0 || seenOuter[r.Hop] {
			continue
		}
		if r.OuterTTL > 64 || r.OuterTTL == 255 {
			seenOuter[r.Hop] = true
			out = append(out, Anomaly{Kind: "outer-ttl", TTL: r.Hop, Devices: []string{p.deviceOf(r.ReplyAddr)},
				Confidence: 0.8,
				Detail:     fmt.Sprintf("reply outer TTL %d at hop %d is not a plausible 64-minus-distance value; distances inferred from it would be wrong", r.OuterTTL, r.Hop)})
		}
	}
	prev := 0.0
	for ttl := 1; ttl <= maxTTL; ttl++ {
		rtt := p.minRTT(ttl)
		if rtt <= 0 {
			continue
		}
		if prev > 0 && rtt < prev*0.6 {
			out = append(out, Anomaly{Kind: "asymmetric-return", TTL: ttl, Devices: []string{p.deviceOf(p.repAddrAt(ttl))},
				Confidence: 0.7,
				Detail:     fmt.Sprintf("round-trip time drops from %.1fms at hop %d to %.1fms at hop %d; the return path differs from the forward path", prev, ttl-1, rtt, ttl)})
		}
		prev = rtt
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].TTL < out[j].TTL
	})
	return out
}

func (p *prober) quirkStats() (silent, hiding, rateLimited, asymmetric int) {
	for _, a := range p.anomalies() {
		switch a.Kind {
		case "silent-hop":
			silent++
		case "ttl-hiding":
			hiding++
		case "rate-limited":
			rateLimited++
		case "asymmetric-return":
			asymmetric++
		}
	}
	return
}

func (p *prober) minRTT(ttl int) float64 {
	best := 0.0
	for _, r := range p.records {
		if r.Hop != ttl || r.ReplyKind == "none" || r.RTTMs <= 0 {
			continue
		}
		if best == 0 || r.RTTMs < best {
			best = r.RTTMs
		}
	}
	return best
}

func (p *prober) repAddrAt(ttl int) string {
	best := ""
	bestN := 0
	for a, n := range p.hopAddrs[ttl] {
		if n > bestN {
			bestN = n
			best = a
		}
	}
	return best
}

func minTTL(m map[int]bool) int {
	best := 1 << 30
	for k := range m {
		if k < best {
			best = k
		}
	}
	return best
}

func sortedInts(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
