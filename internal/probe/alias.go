package probe

import (
	"fmt"
	"sort"
)

// cluster groups reply addresses that belong to the same physical device.
//
// Three signals are combined; all are available to a real prober that only
// sees replies:
//
//  1. IP-ID interleaving.  A device with a global IP-ID counter emits replies
//     from all its interfaces out of one monotonically increasing sequence.
//     If address A's reply at probe i and address B's reply at probe j (the
//     next reply in the stream) advance that sequence by a small, stable
//     amount, A and B are the same device.  This is the classic "IP-ID side
//     channel" alias resolver.
//
//  2. Reply co-occurrence.  Different interfaces of one device appear at the
//     same TTL position across flows: the device is one hop, whoever answers.
//
//  3. Prefix affinity.  Interfaces of one device are usually numbered inside
//     one management/loopback block.  Weak on its own; used to avoid merging
//     across prefixes unless IP-ID evidence is strong.
type cluster struct {
	id     string
	addrs  []string
	method map[string]bool
	score  float64
	ipid   string
}

type idObs struct {
	addr string
	id   uint16
	ttl  int
	seq  int
}

func (p *prober) cluster(recs []Record) {
	// Reply addresses seen at each TTL position.
	byTTL := map[int]map[string]int{}
	addrs := map[string]bool{}
	ttlOf := map[string]map[int]bool{}
	for _, r := range recs {
		if r.ReplyAddr == "" || r.ReplyKind == "none" {
			continue
		}
		if byTTL[r.Hop] == nil {
			byTTL[r.Hop] = map[string]int{}
		}
		byTTL[r.Hop][r.ReplyAddr]++
		addrs[r.ReplyAddr] = true
		if ttlOf[r.ReplyAddr] == nil {
			ttlOf[r.ReplyAddr] = map[int]bool{}
		}
		ttlOf[r.ReplyAddr][r.Hop] = true
	}
	if len(addrs) == 0 {
		p.clusters = nil
		return
	}
	var all []string
	for a := range addrs {
		all = append(all, a)
	}
	sort.Strings(all)

	// Per-address ID behaviour.
	ids := map[string][]uint16{}
	for _, r := range recs {
		if r.ReplyAddr == "" || r.ReplyKind == "none" {
			continue
		}
		ids[r.ReplyAddr] = append(ids[r.ReplyAddr], uint16(r.ReplyIPID))
	}
	cls := map[string]*classOf{}
	for a, vs := range ids {
		cls[a] = classifyIDs(vs)
	}

	parent := map[string]string{}
	var find func(string) string
	find = func(a string) string {
		for parent[a] != "" && parent[a] != a {
			a = parent[a]
		}
		return a
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		if ra < rb {
			parent[rb] = ra
		} else {
			parent[ra] = rb
		}
	}
	method := map[string]map[string]bool{}

	// Signal 1: IP-ID proximity at close observation times.
	//
	// A device's identification counter is shared by all the addresses it
	// originates replies from (global mode) or is per-address but starts from
	// one base (per-address mode).  Either way, two addresses of the same
	// device report IDs that are close whenever they are observed close
	// together.  Two unrelated devices have unrelated bases and drift apart.
	// This is the increment-pattern side channel.
	var stream []idObs
	seq := 0
	for _, r := range recs {
		if r.ReplyAddr == "" || r.ReplyKind == "none" {
			continue
		}
		if c := cls[r.ReplyAddr]; c == nil || c.zero || c.rand {
			continue // no usable counter
		}
		stream = append(stream, idObs{addr: r.ReplyAddr, id: uint16(r.ReplyIPID), ttl: r.Hop, seq: seq})
		seq++
	}
	// Level of an address is its smallest answering TTL across the whole
	// record set (not just the monotone stream): two addresses of one device
	// answer within one hop of each other, devices on different layers do not.
	ttlOfAddr := map[string]int{}
	for _, r := range recs {
		if r.ReplyAddr == "" || r.ReplyKind == "none" {
			continue
		}
		if cur, ok := ttlOfAddr[r.ReplyAddr]; !ok || r.Hop < cur {
			ttlOfAddr[r.ReplyAddr] = r.Hop
		}
	}
	// Stream entries were filtered to usable counters, but classifyIDs runs on
	// each address's full observation list, which for a reused (NAT-like)
	// address can look non-monotone.  What matters to the test is whether the
	// *interleaved* stream is monotone, so use that for the gate.
	streamMono := map[string]*classOf{}
	byAddr := map[string][]uint16{}
	for _, o := range stream {
		byAddr[o.addr] = append(byAddr[o.addr], o.id)
	}
	for a, vs := range byAddr {
		streamMono[a] = classifyIDs(vs)
	}
	usable := func(c *classOf) bool { return c != nil && !c.zero && !c.rand }
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			a, b := all[i], all[j]
			ca, cb := streamMono[a], streamMono[b]
			if !usable(ca) || !usable(cb) {
				continue
			}
			ok, _ := idProximity(stream, a, b)
			if !ok {
				continue
			}
			// Two addresses that answer at very different depths are two
			// devices that happen to sit close in ID space (initial offsets
			// collide); a real device answers within one hop of itself,
			// allowing for keyed TTL handling of at most 1.
			if d := absi(ttlOfAddr[a] - ttlOfAddr[b]); d > 1 {
				continue
			}
			// Two interfaces of one device answer at the same router position.
			// A device that hides a hop (non-standard decrement) answers one
			// TTL later than its upstream neighbour, so a 1-TTL difference is
			// only acceptable when *both* are loopbacks or when exactly one
			// side is a loopback of the other's block -- i.e. never assume
			// same-device across a TTL step when the upstream is a real
			// interface.  Adjacent devices in a chain differ by one TTL and
			// must not merge.
			if ttlOfAddr[a] != ttlOfAddr[b] {
				continue
			}
			union(a, b)
			addMethod(method, a, "ipid")
			addMethod(method, b, "ipid")
		}
	}

	// Signal 2: within one stable flow, several addresses answering at the
	// same TTL are one device.  Under per-flow or per-destination balancing a
	// fixed header tuple follows one path, and a hop on one path is a single
	// device -- whoever among its interfaces answers.  This is the only alias
	// evidence available for devices with random or zero IP-IDs, and it also
	// works for devices whose IDs we could not test.
	type flowTTL struct {
		flow string
		ttl  int
	}
	seenIn := map[flowTTL]map[string]int{}
	for _, r := range recs {
		if r.ReplyAddr == "" || r.ReplyKind == "none" {
			continue
		}
		if r.FlowGroup != "scan" {
			continue
		}
		// A hop downstream of a per-packet router is also effectively
		// per-packet: the same flow tuple legitimately reaches different
		// devices there, so same-flow co-occurrence proves nothing about
		// aliasing.  Inherit the condition upstream.
		if p.packetish(r.Hop) {
			continue
		}
		// The identification field is regenerated per packet and is not part
		// of the routing tuple; including it would make every probe its own
		// flow.
		flowID := fmt.Sprintf("%d/%d/%d/%d", r.SrcPort, r.DstPort, r.Proto, r.TOS)
		k := flowTTL{flowID, r.Hop}
		if seenIn[k] == nil {
			seenIn[k] = map[string]int{}
		}
		seenIn[k][r.ReplyAddr]++
	}
	// Only adopt an address into the group when it answered a meaningful
	// share of that flow's probes at the hop.  A rate-limited device in a
	// pool drops many probes; a stray one-off reply from a neighbour is not
	// enough to merge.
	pairFlows := map[[2]string]int{}
	seenFlows := map[string]map[string]int{}
	for k, set := range seenIn {
		if len(set) < 2 {
			continue
		}
		total := 0
		for _, n := range set {
			total += n
		}
		var kept []string
		for a, n := range set {
			if float64(n)/float64(total) >= 0.2 && n >= 2 {
				kept = append(kept, a)
			}
		}
		if len(kept) < 2 {
			continue
		}
		sort.Strings(kept)
		for i := 0; i < len(kept); i++ {
			if seenFlows[k.flow] == nil {
				seenFlows[k.flow] = map[string]int{}
			}
			seenFlows[k.flow][kept[i]]++
			for j := i + 1; j < len(kept); j++ {
				pairFlows[[2]string{kept[i], kept[j]}]++
			}
		}
	}
	_ = seenFlows
	// Build per-flow sequences so a candidate pair can be checked for
	// downstream lockstep.  Two interfaces of one device answer the same
	// downstream device; two real devices at a fork send the probe to
	// different next hops.
	type step struct{ here, next string }
	flowSeq := map[string]map[int][]step{}
	for _, r := range recs {
		if r.ReplyAddr == "" || r.ReplyKind == "none" || r.FlowGroup != "scan" {
			continue
		}
		flowID := fmt.Sprintf("%d/%d/%d/%d", r.SrcPort, r.DstPort, r.Proto, r.TOS)
		if flowSeq[flowID] == nil {
			flowSeq[flowID] = map[int][]step{}
		}
		flowSeq[flowID][r.Hop] = append(flowSeq[flowID][r.Hop], step{here: r.ReplyAddr})
	}
	for _, byHop := range flowSeq {
		for ttl, steps := range byHop {
			nextSteps := byHop[ttl+1]
			for i := range steps {
				if i < len(nextSteps) {
					steps[i].next = nextSteps[i].here
				}
			}
			byHop[ttl] = steps
		}
	}
	downstreamMoves := func(a, b string, ttl int) bool {
		// true when choosing between a and b changes the next hop in a
		// majority of flows -- real ECMP, not aliasing.
		moved, seen := 0, 0
		for _, byHop := range flowSeq {
			steps := byHop[ttl]
			nextFor := map[string]map[string]int{}
			for _, st := range steps {
				if st.next == "" {
					continue
				}
				if nextFor[st.here] == nil {
					nextFor[st.here] = map[string]int{}
				}
				nextFor[st.here][st.next]++
			}
			na, nb := nextFor[a], nextFor[b]
			if len(na) == 0 || len(nb) == 0 {
				continue
			}
			seen++
			diff := false
			for x := range na {
				for y := range nb {
					if x != y {
						diff = true
					}
				}
			}
			if diff {
				moved++
			}
		}
		return seen > 0 && float64(moved)/float64(seen) >= 0.6
	}
	for pair, n := range pairFlows {
		if n < 1 {
			continue
		}
		if ttlOfAddr2(recs, pair[0]) != ttlOfAddr2(recs, pair[1]) {
			continue
		}
		if downstreamMoves(pair[0], pair[1], ttlOfAddr2(recs, pair[0])) {
			continue // a real fork: the two addresses lead to different hops
		}
		// Both members must be consistently multi-address at that TTL: else a
		// single slow answer from another device would pull it in.
		if !consistentAt(recs, pair[0]) || !consistentAt(recs, pair[1]) {
			continue
		}
		union(pair[0], pair[1])
		addMethod(method, pair[0], "same-flow")
		addMethod(method, pair[1], "same-flow")
	}

	// Build clusters.
	buckets := map[string]*cluster{}
	var order []string
	for _, a := range all {
		r := find(a)
		c := buckets[r]
		if c == nil {
			c = &cluster{method: map[string]bool{}}
			buckets[r] = c
			order = append(order, r)
		}
		c.addrs = append(c.addrs, a)
		for m := range method[a] {
			c.method[m] = true
		}
	}
	sort.Strings(order)
	out := make([]*cluster, 0, len(order))
	for i, r := range order {
		c := buckets[r]
		sort.Strings(c.addrs)
		c.id = fmt.Sprintf("dev%d", i+1)
		switch {
		case (c.method["ipid"] || c.method["ipid-window"] || c.method["same-flow"]) && len(c.addrs) > 1:
			c.score = 0.92
		case c.method["co-occur"]:
			c.score = 0.8
		case c.method["prefix"]:
			c.score = 0.5
		case len(c.addrs) == 1:
			c.score = 0.7 // singular: no alias claim to make
		}
		mono, rnd, zero := 0, 0, 0
		for _, a := range c.addrs {
			cl := cls[a]
			if cl == nil {
				continue
			}
			switch {
			case cl.mono:
				mono++
			case cl.rand:
				rnd++
			case cl.zero:
				zero++
			}
		}
		switch {
		case len(c.addrs) > 0 && zero == len(c.addrs):
			c.ipid = "zero"
		case rnd > 0 && mono == 0:
			c.ipid = "random"
		case mono > 0:
			c.ipid = "incrementing"
		default:
			c.ipid = "unknown"
		}
		out = append(out, c)
	}
	p.clusters = out
	p.addrToDev = map[string]string{}
	for _, c := range out {
		for _, a := range c.addrs {
			p.addrToDev[a] = c.id
		}
		p.devIPID[c.id] = c.ipid
	}
}

func addMethod(m map[string]map[string]bool, a, how string) {
	if m[a] == nil {
		m[a] = map[string]bool{}
	}
	m[a][how] = true
}

// classOf is the observed IP-ID behaviour of one address.
type classOf struct {
	mono bool
	rand bool
	zero bool
}

func classifyIDs(vs []uint16) *classOf {
	c := &classOf{}
	if len(vs) == 0 {
		return c
	}
	zeros := 0
	for _, v := range vs {
		if v == 0 {
			zeros++
		}
	}
	if zeros == len(vs) {
		c.zero = true
		return c
	}
	fwd, back, steps := 0, 0, 0
	for i := 1; i < len(vs); i++ {
		d := int(vs[i]) - int(vs[i-1])
		if d < -32768 {
			d += 65536
		}
		if d > 32768 {
			d -= 65536
		}
		steps++
		if d > 0 {
			fwd++
		} else if d < 0 {
			back++
		}
	}
	switch {
	case steps == 0:
		c.mono = false
	case fwd >= int(0.85*float64(steps)) && back <= int(0.15*float64(steps)):
		c.mono = true
	default:
		c.rand = true
	}
	return c
}

// idProximity tests whether two addresses share an identification counter, or
// at least one base value, by comparing their IDs at close observation times.
//
// For every observation of a, the nearest following observation of b within a
// few replies is paired and the signed difference is recorded.  A shared
// counter keeps |difference| within the number of intervening replies; two
// independent devices show their base offset, which is large and constant.
func idProximity(stream []idObs, a, b string) (bool, float64) {
	if countAddr(stream, a) < 6 || countAddr(stream, b) < 6 {
		return false, 0
	}
	// For each reply of a, take the next reply of b (and vice versa) within a
	// short window.  Two interfaces of one device answer out of one counter,
	// so that transition advances the ID by the few packets the device sent
	// in between -- always positive and small.  Two unrelated devices have
	// independent counters: the difference carries their base offset and is
	// large or negative about half the time.
	var diffs []int
	nextA, nextB := -1, -1
	for i, o := range stream {
		switch o.addr {
		case a:
			if nextB >= 0 && i-nextB <= 4 {
				diffs = append(diffs, wrapDiff(int(o.id), int(stream[nextB].id)))
			}
			nextA = i
		case b:
			if nextA >= 0 && i-nextA <= 4 {
				diffs = append(diffs, wrapDiff(int(o.id), int(stream[nextA].id)))
			}
			nextB = i
		}
	}
	if len(diffs) < 4 {
		return false, 0
	}
	// A per-address counter may sit one or two ahead of the shared base, so
	// the cross-address difference can be a small *negative* number as well.
	// What identifies a shared device is that the difference is small and
	// stable in magnitude, whichever counter is momentarily ahead.
	good := 0
	var abs []int
	for _, d := range diffs {
		if d >= -8 && d <= 8 {
			good++
			if d < 0 {
				d = -d
			}
			abs = append(abs, d)
		}
	}
	frac := float64(good) / float64(len(diffs))
	if frac < 0.85 {
		return false, frac
	}
	sort.Ints(abs)
	med := abs[len(abs)/2]
	if med > 4 {
		return false, frac
	}
	return true, frac * (1 - float64(med)/16)
}

// packetish reports whether the hop is, or is downstream of, a per-packet
// balancer.  Such hops cannot use same-flow co-occurrence as alias evidence.
func (p *prober) packetish(ttl int) bool {
	for t := 1; t <= ttl; t++ {
		if p.spray[t] >= 0.3 || p.lbMode[t] == "per-packet" {
			return true
		}
	}
	return false
}

func absi(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func ttlOfAddr2(recs []Record, addr string) int {
	best := 1 << 30
	for _, r := range recs {
		if r.ReplyAddr == addr && r.ReplyKind != "none" && r.Hop < best {
			best = r.Hop
		}
	}
	if best == 1<<30 {
		return 0
	}
	return best
}

func countAddr(stream []idObs, a string) int {
	n := 0
	for _, o := range stream {
		if o.addr == a {
			n++
		}
	}
	return n
}

func wrapDiff(x, y int) int {
	d := x - y
	if d < -32768 {
		d += 65536
	}
	if d > 32768 {
		d -= 65536
	}
	return d
}

func same24(a, b string) bool {
	x, y := split24(a), split24(b)
	return x != "" && x == y
}

func split24(s string) string {
	o := splitOctets(s)
	if len(o) != 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", o[0], o[1], o[2])
}

func ttlNear(a, b map[int]bool) bool {
	for x := range a {
		if b[x] || b[x+1] || b[x-1] {
			return true
		}
	}
	return false
}

func toClusters(cs []*cluster) []NodeCluster {
	out := make([]NodeCluster, 0, len(cs))
	for _, c := range cs {
		var ms []string
		for _, m := range []string{"prefix", "ipid"} {
			if c.method[m] {
				ms = append(ms, m)
			}
		}
		out = append(out, NodeCluster{ID: c.id, Addrs: c.addrs, Confidence: c.score, Method: ms, IPIDMode: c.ipid})
	}
	return out
}

// consistentAt reports whether the address replies to most probes at its
// level, i.e. it is a real responder rather than a one-off stray.
func consistentAt(recs []Record, addr string) bool {
	lvl := ttlOfAddr2(recs, addr)
	sent, ans := 0, 0
	for _, r := range recs {
		if r.Hop != lvl || r.FlowGroup != "scan" {
			continue
		}
		sent++
		if r.ReplyAddr == addr {
			ans++
		}
	}
	if sent == 0 {
		return false
	}
	return float64(ans)/float64(sent) >= 0.1
}
