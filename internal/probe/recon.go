package probe

import (
	"fmt"
	"sort"

	"topomap/internal/sim"
)

// recon is pass A: one reference flow walked up the TTL axis, plus a small
// source-port spray at every hop, to enumerate the candidate addresses per
// depth.  Those addresses are then clustered so later passes can tell a
// multi-interface device from a genuine fork.
func (p *prober) recon() {
	base := p.baseProbe(0)
	for ttl := 1; ttl <= 40 && p.budgetLeft(); ttl++ {
		q := base
		q.TTL = ttl
		rep := p.send(q, "recon")
		p.hopPkts[ttl]++
		if rep.Kind != sim.ReplyNone {
			p.hopAddrsInit(ttl)[rep.SrcAddr]++
			p.noteHopDev(ttl, rep.SrcAddr)
		} else {
			p.hopNone[ttl]++
		}
		// Spray a few source/dest ports to expose siblings and reply pools.
		for i := 0; i < 5 && p.budgetLeft(); i++ {
			r := base
			r.TTL = ttl
			r.SrcPort = uint16(30000 + ttl*100 + i*17)
			r.DstPort = uint16(33434 + i*29)
			rr := p.send(r, "recon-spray")
			p.hopPkts[ttl]++
			if rr.Kind != sim.ReplyNone {
				p.hopAddrsInit(ttl)[rr.SrcAddr]++
				p.noteHopDev(ttl, rr.SrcAddr)
			} else {
				p.hopNone[ttl]++
			}
		}
		if rep.Kind == sim.ReplyEcho {
			p.depth = ttl
			break
		}
		if rep.Kind != sim.ReplyNone {
			p.depth = ttl
		}
	}
	if p.depth == 0 {
		p.depth = 16
		p.warnings = append(p.warnings, "destination never answered; depth capped at 16")
	}
	// Leave room past the destination: the TTL axis is in units of routers,
	// not path length, and the scan discovers the endpoint itself.
	p.depth += 2
}

func (p *prober) hopAddrsInit(ttl int) map[string]int {
	if p.hopAddrs[ttl] == nil {
		p.hopAddrs[ttl] = map[string]int{}
	}
	return p.hopAddrs[ttl]
}

// detectLB is pass B: per-hop classification of the balancing policy and the
// header fields that steer it.
//
// At every hop that currently looks multi-device, pairs of probes are sent
// that differ in exactly one header field.  A field whose variation moves the
// answer to a different device is a steering field at that hop.  Eight
// identical probes distinguish per-packet spraying (identical tuples split)
// from per-flow hashing (identical tuples are stable).
func (p *prober) detectLB() {
	// Phase B1: ten identical probes per multi-address hop reveal whether the
	// hop sprays per packet.  Identical tuples must stay put under per-flow
	// and per-destination balancing.
	type hopSeq struct {
		addrs []string
	}
	seqs := map[int]*hopSeq{}
	var multi []int
	for ttl := 2; ttl <= p.depth && p.budgetLeft(); ttl++ {
		if p.hopPkts[ttl] == 0 {
			continue
		}
		multi = append(multi, ttl)
		base := p.baseProbe(0)
		base.TTL = ttl
		sq := &hopSeq{}
		for i := 0; i < 10 && p.budgetLeft(); i++ {
			rep := p.send(base, "packet-test")
			p.hopPkts[ttl]++
			if rep.Kind == sim.ReplyNone {
				p.hopNone[ttl]++
				continue
			}
			p.hopAddrsInit(ttl)[rep.SrcAddr]++
			sq.addrs = append(sq.addrs, rep.SrcAddr)
		}
		seqs[ttl] = sq
	}
	// The identical-probe bursts add fresh evidence; re-cluster so that
	// round-robin addresses of one device are recognised before we decide a
	// hop sprays.
	p.cluster(p.records)

	// Phase B2: score the sequences and sweep fields at stable hops.
	for _, ttl := range multi {
		if !p.budgetLeft() {
			break
		}
		base := p.baseProbe(0)
		base.TTL = ttl
		sq := seqs[ttl]
		changes := 0
		for i := 1; i < len(sq.addrs); i++ {
			if p.deviceOf(sq.addrs[i]) != p.deviceOf(sq.addrs[i-1]) {
				changes++
			}
		}
		spray := 0.0
		if len(sq.addrs) > 1 {
			spray = float64(changes) / float64(len(sq.addrs)-1)
		}
		p.spray[ttl] = spray
		p.trace("hop %d: %d devices among %d replies, spray=%.2f", ttl, len(p.hopDevs[ttl]), len(sq.addrs), spray)
		p.hopFields[ttl] = map[sim.HashField]*fstat{}
		if len(p.hopDevs[ttl]) < 2 {
			// One downstream device in the main run.  Before concluding there
			// is nothing to balance to, vary the destination prefix, which is
			// the one dimension the reference flow never touches.
			moved := p.destMovesElsewhere(base, ttl)
			if !moved {
				continue
			}
			p.lbMode[ttl] = "per-destination"
		}
		_ = base
		if spray >= 0.3 {
			p.lbMode[ttl] = "per-packet"
			continue
		}
		k := p.branchEstimate(ttl)
		if k < 2 {
			k = 2 // give a per-destination hop at least a few prefix pairs
		}
		for _, f := range sim.AllHashFields {
			if p.lbMode[ttl] == "per-destination" && f != sim.FieldDstIP {
				continue
			}
			st := &fstat{}
			p.hopFields[ttl][f] = st
			n := k * p.opts.FieldSweepSamples
			if n > 3*p.opts.FieldSweepSamples {
				n = 3 * p.opts.FieldSweepSamples
			}
			// Paired design: two probes that differ only in f, with two
			// different values.  If f is in the hop's hash the pair lands on
			// independent branches; if it is not, both land on the branch the
			// other (fixed) fields select.  The null therefore predicts zero
			// disagreement, not one half.
			//
			// Sampling is sequential: a field with no disagreements after a
			// handful of pairs is ignored, and a field with a high rate and
			// overwhelming confidence steers.  Only genuinely ambiguous fields
			// consume the full budget.
			for i := 0; i < n && p.budgetLeft(); i++ {
				a := p.vary(base, f, 101+i*13)
				b := p.vary(base, f, 617+i*29)
				if f == sim.FieldDstIP {
					// Only count a pair when both changed addresses are not
					// simply blackholed; otherwise the comparison is between
					// an answer and silence, not between two branches.
					ra, rb, ok := p.pairWithRetry(a, b, ttl)
					if !ok {
						continue
					}
					st.tried++
					if p.deviceOf(ra.SrcAddr) != p.deviceOf(rb.SrcAddr) {
						st.changed++
					}
					continue
				}
				ra, rb, ok := p.pairWithRetry(a, b, ttl)
				if !ok {
					continue
				}
				st.tried++
				if p.deviceOf(ra.SrcAddr) != p.deviceOf(rb.SrcAddr) {
					st.changed++
				}
			}
		}
	}
	// Assign verdicts and per-hop modes.  The output is per field (global
	// influence: max over hops) and per hop (which fields steer there).
	fieldTried := map[sim.HashField]int{}
	fieldChanged := map[sim.HashField]int{}
	for _, m := range p.hopFields {
		for f, st := range m {
			fieldTried[f] += st.tried
			fieldChanged[f] += st.changed
		}
	}
	var order []sim.HashField
	for _, f := range sim.AllHashFields {
		order = append(order, f)
	}
	// Per-field evidence is aggregated across hops for the human-facing
	// table, but steering decisions use the best hop: a field only matters
	// where a router actually hashes on it, and averaging over hops that
	// ignore it hides the router that uses it.
	best := map[sim.HashField]*fstat{}
	for _, m := range p.hopFields {
		for f, st := range m {
			b := best[f]
			if b == nil || ratio(st.changed, st.tried) > ratio(b.changed, b.tried) {
				best[f] = st
			}
		}
	}
	for _, f := range order {
		t, c := fieldTried[f], fieldChanged[f]
		inf := FieldInfluence{Field: f.String(), Tried: t, Changes: c}
		if t > 0 {
			inf.Influence = float64(c) / float64(t)
			inf.Confidence = binomialConfidence(c, t, 0.05)
		}
		steers := false
		if b := best[f]; b != nil && b.tried >= 3 {
			r := ratio(b.changed, b.tried)
			if r >= 0.25 && binomialConfidence(b.changed, b.tried, 0.05) >= 0.99 {
				steers = true
				inf.Influence = r
				inf.Confidence = binomialConfidence(b.changed, b.tried, 0.05)
				inf.Tried = b.tried
				inf.Changes = b.changed
			}
		}
		switch {
		case t == 0:
			inf.Verdict = "untested"
		case steers:
			inf.Verdict = "steers"
			p.steering = append(p.steering, f)
		case inf.Influence <= 0.10:
			inf.Verdict = "ignored"
		default:
			inf.Verdict = "inconclusive"
		}
		p.fields = append(p.fields, inf)
	}
	sort.SliceStable(p.fields, func(i, j int) bool { return p.fields[i].Field < p.fields[j].Field })

	// Per-hop mode where not already per-packet.
	for ttl := 2; ttl <= p.depth; ttl++ {
		if p.lbMode[ttl] != "" || len(p.hopAddrs[ttl]) < 2 {
			continue
		}
		if p.hopDestSteers(ttl) && !p.hopFieldSteers(ttl, sim.FieldSrcPort) && !p.hopFieldSteers(ttl, sim.FieldDstPort) {
			p.lbMode[ttl] = "per-destination"
			continue
		}
		if len(p.hopFields[ttl]) == 0 {
			continue
		}
		p.lbMode[ttl] = "per-flow"
	}
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func (p *prober) hopFieldSteers(ttl int, f sim.HashField) bool {
	m := p.hopFields[ttl]
	if m == nil || m[f] == nil || m[f].tried < 2 {
		return false
	}
	return ratio(m[f].changed, m[f].tried) >= 0.8
}

func (p *prober) hopDestSteers(ttl int) bool {
	return p.hopFieldSteers(ttl, sim.FieldDstIP)
}

// pairWithRetry sends probe a and the reference probe b at a TTL, retrying
// the pair when a reply is lost, so that ICMP rate limiting does not look
// like a routing change.  Returns once both answered.
func (p *prober) pairWithRetry(a, b sim.Probe, ttl int) (sim.Reply, sim.Reply, bool) {
	a.TTL, b.TTL = ttl, ttl
	for attempt := 0; attempt < 4 && p.budgetLeft(); attempt++ {
		ra := p.send(a, "field-sweep")
		rb := p.send(b, "field-sweep")
		p.hopPkts[ttl] += 2
		for _, rr := range []sim.Reply{ra, rb} {
			if rr.Kind == sim.ReplyNone {
				p.hopNone[ttl]++
			} else {
				p.hopAddrsInit(ttl)[rr.SrcAddr]++
				p.noteHopDev(ttl, rr.SrcAddr)
			}
		}
		if ra.Kind != sim.ReplyNone && rb.Kind != sim.ReplyNone {
			return ra, rb, true
		}
	}
	return sim.Reply{}, sim.Reply{}, false
}

// branchEstimate is a quick multiplicity estimate for a hop: the number of
// distinct reply devices seen in a short spray of distinct flows, capped so
// the field sweep stays affordable.
func (p *prober) branchEstimate(ttl int) int {
	base := p.baseProbe(0)
	seen := map[string]bool{}
	for i := 0; i < 8 && p.budgetLeft(); i++ {
		q := base
		q.TTL = ttl
		q.SrcPort = uint16(26000 + i*311)
		q.DstPort = uint16(33434 + i*37)
		rep := p.send(q, "branch-estimate")
		p.hopPkts[ttl]++
		if rep.Kind == sim.ReplyNone {
			p.hopNone[ttl]++
			continue
		}
		p.hopAddrsInit(ttl)[rep.SrcAddr]++
		p.noteHopDev(ttl, rep.SrcAddr)
		seen[p.deviceOf(rep.SrcAddr)] = true
	}
	if len(seen) < 2 {
		return 1
	}
	return len(seen)
}

// repeatability sends the same header tuple n times and reports the fraction
// of consecutive reply pairs that landed on different devices.  It also
// returns whether the sequence was stable enough to trust a field sweep.
func (p *prober) repeatability(q sim.Probe, ttl, n int) (float64, bool) {
	var seq []string
	for i := 0; i < n && p.budgetLeft(); i++ {
		rep := p.send(q, "packet-test")
		p.hopPkts[ttl]++
		if rep.Kind == sim.ReplyNone {
			p.hopNone[ttl]++
			continue
		}
		p.hopAddrsInit(ttl)[rep.SrcAddr]++
		p.noteHopDev(ttl, rep.SrcAddr)
		seq = append(seq, p.deviceOf(rep.SrcAddr))
	}
	if len(seq) < 2 {
		return 0, false
	}
	changes := 0
	for i := 1; i < len(seq); i++ {
		if seq[i] != seq[i-1] {
			changes++
		}
	}
	return float64(changes) / float64(len(seq)-1), len(seq) >= n/2
}

// destMovesElsewhere varies the destination prefix and checks whether the
// answering device at this TTL changes, without changing any other field.
func (p *prober) destMovesElsewhere(base sim.Probe, ttl int) bool {
	here := p.deviceOf(p.repAddrAt(ttl))
	for i := 0; i < 6 && p.budgetLeft(); i++ {
		q := base
		q.TTL = ttl
		o := splitOctets(p.dst)
		if len(o) != 4 {
			return false
		}
		q.DstIP = ipv4(fmt.Sprintf("%d.%d.%d.1", 198, 100+i, 7), o[3])
		rep := p.send(q, "dest-sweep")
		p.hopPkts[ttl]++
		if rep.Kind == sim.ReplyNone {
			p.hopNone[ttl]++
			continue
		}
		p.hopAddrsInit(ttl)[rep.SrcAddr]++
		p.noteHopDev(ttl, rep.SrcAddr)
		if p.deviceOf(rep.SrcAddr) != here {
			return true
		}
	}
	return false
}
