package probe

import (
	"math"
	"sort"

	"topomap/internal/sim"
)

// chooseFlows builds the header tuples used by the main scan.
//
// Diversity comes only from fields shown to steer, plus the ports (which are
// unavoidably part of a flow).  Fields shown to be ignored are pinned so all
// probes in one flow stay on one path.
func (p *prober) chooseFlows() {
	// Plan a Cartesian product over every *candidate* field except the ones a
	// hop was actually observed to ignore.  Steering fields are known to
	// matter; fields that were merely inconclusive (common when the only
	// router hashing them sits behind a TTL-hiding or silent hop) are still
	// varied, because leaving them pinned guarantees that router's branches
	// are never visited.  Only fields tested and found inert are pinned.
	ignored := map[sim.HashField]bool{}
	for _, inf := range p.fields {
		if inf.Verdict == "ignored" {
			ignored[fieldByName(inf.Field)] = true
		}
	}
	var steer []sim.HashField
	for _, f := range sim.AllHashFields {
		if ignored[f] || f == sim.FieldDstIP {
			// The destination is held fixed: this scan maps one destination.
			continue
		}
		steer = append(steer, f)
	}
	if len(steer) == 0 {
		steer = []sim.HashField{sim.FieldSrcPort}
	}
	// Round-robin port values provide the diversity even if the sweep
	// misfired; they are always part of the flow anyway.
	vals := []int{11, 37, 73, 109, 151, 197}
	seen := map[string]bool{}
	add := func(q sim.Probe) {
		q.DstIP = p.dst // never leave the destination prefix
		k := FlowKey(q)
		if seen[k] || len(p.flows) >= p.opts.MaxFlows {
			return
		}
		seen[k] = true
		p.flows = append(p.flows, q)
	}
	// Cartesian product, capped by MaxFlows.  Ignored fields stay at base.
	var rec func(idx int, q sim.Probe)
	rec = func(idx int, q sim.Probe) {
		if len(p.flows) >= p.opts.MaxFlows {
			return
		}
		if idx == len(steer) {
			add(q)
			return
		}
		f := steer[idx]
		for i, v := range vals {
			r := p.vary(q, f, v)
			if f == sim.FieldProto {
				r.Proto = uint8(6 + (i%2)*11)
			}
			rec(idx+1, r)
		}
	}
	base := p.baseProbe(0)
	for i, v := range vals {
		q := p.vary(base, sim.FieldSrcPort, v)
		q.DstPort = uint16(33434 + vals[i]*7)
		_ = i
		rec(0, q)
	}
	// Exploration flows: after the planned product, spend the remaining flow
	// budget on tuples that vary every candidate field at once.  Some routers
	// (behind silent or TTL-hiding hops) only reveal a branch for a
	// combination the field sweep could not attribute, and a small random
	// cover finds those without weakening any individual flow's stability.
	for i := 0; len(p.flows) < p.opts.MaxFlows; i++ {
		q := p.baseProbe(i)
		q.SrcPort = uint16(21000 + (i*97)%20000)
		q.DstPort = uint16(33434 + (i*53)%20000)
		q.Proto = uint8([]int{17, 6, 1, 132}[i%4])
		q.TOS = uint8((i % 8) * 16)
		q.IPID = uint16((i*7919 + 3) & 0xffff)
		q.FlowLabel = uint32(i*104729 + 7)
		add(q)
		if i > 4000 {
			break
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// scan walks every flow up the TTL axis, sampling each hop until the
// statistical stopping rule says the branch set is complete.
//
// A flow stops when the destination echoes back; for the remaining flows the
// echo probe at each depth is the authority on whether the endpoint has been
// reached.
func (p *prober) scan() {
	for fi, base := range p.flows {
		if !p.budgetLeft() {
			p.warnings = append(p.warnings, "probe budget exhausted before all flows were explored")
			break
		}
		p.trace("flow %d/%d start after %d probes", fi+1, len(p.flows), p.probes)
		path := &Path{ID: fi, FlowKey: FlowKey(base)}
		path.Hops = make([]string, p.depth+1)
		path.RTT = make([]float64, p.depth+1)
		for ttl := 1; ttl <= p.depth && p.budgetLeft(); ttl++ {
			q := base
			q.TTL = ttl
			addrs := map[string]int{}
			none := 0
			sent := 0
			maxSent := p.opts.MaxProbesPerFlow
			reachedDest := false
			for sent < maxSent && p.budgetLeft() {
				if sent >= p.opts.MinSamplesPerHop && p.hopComplete(addrs, sent, none) {
					break
				}
				qq := q
				qq.IPID = uint16(p.rng.Intn(65536))
				rep := p.send(qq, "scan")
				sent++
				path.Attempts++
				p.hopPkts[ttl]++
				if rep.Kind == sim.ReplyNone {
					none++
					p.hopNone[ttl]++
					// Rate-limited hops are common; keep probing the hop to
					// give the responder its next token rather than treating
					// loss as a signal.
					continue
				}
				addrs[rep.SrcAddr]++
				p.hopAddrsInit(ttl)[rep.SrcAddr]++
				p.noteHopDev(ttl, rep.SrcAddr)
				if path.Hops[ttl] == "" || rep.RTTMs < path.RTT[ttl] {
					path.Hops[ttl] = rep.SrcAddr
					path.RTT[ttl] = rep.RTTMs
				}
			}
			// The TTL-expired probe is not evidence that this flow contains
			// the destination.  One echo probe per depth settles it.
			check := base
			check.TTL = ttl
			check.IPID = uint16(p.rng.Intn(65536))
			rep := p.send(check, "dst-check")
			p.hopPkts[ttl]++
			p.rounds++
			if rep.Kind == sim.ReplyEcho {
				reachedDest = true
				path.Hops[ttl] = rep.SrcAddr
				path.RTT[ttl] = rep.RTTMs
				p.hopAddrsInit(ttl)[rep.SrcAddr]++
				p.noteHopDev(ttl, rep.SrcAddr)
			} else if rep.Kind == sim.ReplyNone {
				p.hopNone[ttl]++
			} else {
				p.hopAddrsInit(ttl)[rep.SrcAddr]++
				p.noteHopDev(ttl, rep.SrcAddr)
			}
			p.rounds++
			path.Weight += sent
			if reachedDest {
				break
			}
		}
		p.paths = append(p.paths, path)
	}
}

func (p *prober) noteHopDev(ttl int, addr string) {
	if p.hopDevs[ttl] == nil {
		p.hopDevs[ttl] = map[string]int{}
	}
	p.hopDevs[ttl][p.deviceOf(addr)]++
}

// hopComplete implements the stopping rule.
//
// With n answered probes producing k distinct branches, the probability that
// an unobserved branch carries mass >= m is bounded by (k+1)(1-m)^n: a union
// bound over the unseen slots of a (k+1)-way split.  We stop when, for the
// configured margin m, that bound is at most 1-Confidence.  Raising the
// confidence or lowering the margin therefore directly increases the sample
// count until the unseen-branch bound is exhausted.
func (p *prober) hopComplete(addrs map[string]int, sent, none int) bool {
	n := sent
	if n < p.opts.MinSamplesPerHop {
		return false
	}
	k := len(addrs)
	if k == 0 {
		// A hop that has answered nothing yet is silent only once we have
		// given it enough opportunities to refill a rate limiter; before that
		// the loss is not evidence.
		return sent >= 3*p.opts.MinSamplesPerHop
	}
	// Rate limiting makes raw loss meaningless as a completeness signal: the
	// sample size is answered probes, not sent probes.
	n = sent - none
	if n < p.opts.MinSamplesPerHop {
		return false
	}
	m := p.opts.Margin
	alpha := 1 - p.opts.Confidence
	missing := float64(k+1) * math.Pow(1-m, float64(n))
	if missing > alpha {
		return false
	}
	// Every observed branch must have been seen at least twice, otherwise a
	// single stray reply would count as a branch.
	for _, c := range addrs {
		if c < 2 {
			return false
		}
	}
	return true
}

// estimateHop reports how many next hops a depth has, with an interval, from
// the device histogram (addresses already merged by alias resolution).
//
// The stopping model treats the observed branch frequencies as a multinomial
// sample: after n answered probes, the chance that an unobserved branch holds
// mass m or more is bounded by (k+1)(1-m)^n.  Inverting that bound gives both
// the completion flag and the extra branches the interval must allow for.
func (p *prober) estimateHop(ttl int) HopEstimate {
	est := HopEstimate{TTL: ttl, Confidence: p.opts.Confidence}
	devs := p.hopDevs[ttl]
	total := p.hopPkts[ttl]
	none := p.hopNone[ttl]
	est.Probes = total
	n := total - none
	if n <= 0 || len(devs) == 0 {
		est.Complete = true
		return est
	}
	est.Reached = true
	est.Observed = len(devs)
	k := len(devs)
	m := p.opts.Margin
	alpha := 1 - p.opts.Confidence
	missing := float64(k+1) * math.Pow(1-m, float64(n))
	extra := 0
	if missing > alpha {
		extra = int(math.Ceil(missing / m))
		if extra > 3 {
			extra = 3
		}
		if extra < 1 {
			extra = 1
		}
	}
	est.Estimate = est.Observed + extra
	est.Lower = est.Observed
	est.Upper = est.Observed + extra
	est.Complete = extra == 0
	// A branch that only ever appeared once is not yet a branch.
	for _, c := range devs {
		if c < 2 {
			est.Complete = false
			if est.Upper < est.Observed+1 {
				est.Upper = est.Observed + 1
			}
		}
	}
	return est
}

// binomialConfidence is the confidence that a switch rate exceeds chance.
func binomialConfidence(changed, n int, p0 float64) float64 {
	if n == 0 {
		return 0
	}
	mean := float64(n) * p0
	sigma := math.Sqrt(float64(n) * p0 * (1 - p0))
	if sigma == 0 {
		return 0
	}
	z := (float64(changed) - 0.5 - mean) / sigma
	return 0.5 * (1 + math.Erf(z/math.Sqrt2))
}

func sortedIntKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fieldByName(name string) sim.HashField {
	for _, f := range sim.AllHashFields {
		if f.String() == name {
			return f
		}
	}
	return sim.FieldSrcPort
}
