package probe

import (
	"fmt"
	"sort"

	"topomap/internal/sim"
)

// nodes turns device clusters into graph nodes.  A cluster's level is the
// smallest TTL at which any of its addresses answered; a device that answers
// at several TTLs is a TTL-hiding or over-decrementing device.
func (p *prober) nodes() []FNode {
	lvl := map[string]int{}
	for ttl, m := range p.hopAddrs {
		for a := range m {
			d := p.deviceOf(a)
			if cur, ok := lvl[d]; !ok || ttl < cur {
				lvl[d] = ttl
			}
		}
	}
	// Keep hopDevs consistent with the final clusters.
	p.hopDevs = map[int]map[string]int{}
	for ttl, m := range p.hopAddrs {
		p.hopDevs[ttl] = map[string]int{}
		for a, c := range m {
			p.hopDevs[ttl][p.deviceOf(a)] += c
		}
	}
	devs := sortedDevKeys(lvl)
	nodes := []FNode{{ID: "src", Label: "source " + p.src, Addrs: []string{p.src}, Level: 0, Kind: "src", AliasScore: 1}}
	ids := map[string]string{}
	for i, d := range devs {
		id := fmt.Sprintf("n%d", i+1)
		ids[d] = id
		var addrs []string
		score := 0.7
		for _, c := range p.clusters {
			if c.id == d {
				addrs = append(addrs, c.addrs...)
				score = c.score
				break
			}
		}
		if len(addrs) == 0 {
			addrs = []string{trimPrefix(d, "addr:")}
		}
		sort.Strings(addrs)
		kind := "router"
		for _, a := range addrs {
			if a == p.dst {
				kind = "dst"
			}
		}
		label := addrs[0]
		nodes = append(nodes, FNode{ID: id, Label: label, Addrs: addrs, Level: lvl[d], Kind: kind, AliasScore: score})
	}
	p.devToNode = ids
	// Every reply address a device showed is one of its interfaces.  Add an
	// interface node for each, hanging off the device node, so the graph can be
	// read at either level.
	p.ifaceNodes = nil
	devIndexOf := map[string]int{}
	for i, d := range devs {
		devIndexOf[d] = i
	}
	for _, c := range p.clusters {
		di, ok := devIndexOf[c.id]
		if !ok {
			continue
		}
		for _, a := range c.addrs {
			p.ifaceNodes = append(p.ifaceNodes, IfaceNode{
				Addr: a, Device: ids[c.id], DeviceLabel: c.addrs[0],
				Level: lvl[c.id], Order: di*100 + len(p.ifaceNodes),
			})
		}
	}
	// Make sure the destination is represented.
	foundDst := false
	for _, n := range nodes {
		for _, a := range n.Addrs {
			if a == p.dst {
				foundDst = true
			}
		}
	}
	if !foundDst {
		maxL := 0
		for _, n := range nodes {
			if n.Level > maxL {
				maxL = n.Level
			}
		}
		nodes = append(nodes, FNode{ID: "dst", Label: p.dst, Addrs: []string{p.dst}, Level: maxL + 1, Kind: "dst", AliasScore: 1})
		p.devToNode[p.deviceOf(p.dst)] = "dst"
	}
	return nodes
}

func sortedDevKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] < m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

// links builds the fused edges and the branch table.
//
// One edge per (from-device, to-device) pair that was observed adjacent on a
// path, carrying the number of paths that took it and the RTTs.  A
// transition across silent TTL slots is only recorded when the two devices
// are not already connected by visible edges; otherwise it is the splice
// artifact a naive traceroute produces, and dropping it is the whole point.
func (p *prober) links(nodes []FNode) ([]FLink, []Branch) {
	type key struct{ a, b string }
	agg := map[key]*FLink{}
	rtts := map[key][]float64{}
	level := map[string]int{}
	for _, n := range nodes {
		level[n.ID] = n.Level
	}
	// mixedHop reports whether a flow saw more than one device at a TTL.  That
	// means a per-packet balancer upstream, so the identity of the hop is not
	// stable within the flow and an adjacency across it cannot be asserted.
	mixedHop := func(flowKey string, ttl int) bool {
		m := p.flowMulti[flowKey]
		return m != nil && m[ttl] > 1
	}
	nodeOfDev := func(dev string) string {
		if id, ok := p.devToNode[dev]; ok {
			return id
		}
		return ""
	}
	for _, pa := range p.paths {
		prevDev := "src"
		prevNode := "src"
		_ = prevDev
		silent := 0
		for ttl := 1; ttl < len(pa.Hops); ttl++ {
			a := pa.Hops[ttl]
			if a == "" {
				silent++
				continue
			}
			dev := p.deviceOf(a)
			node := nodeOfDev(dev)
			if node == "" {
				continue
			}
			if node == prevNode {
				continue
			}
			// A device cannot be its own ancestor in a forward path.  If the
			// new node already appears earlier on this path, a probe crossed a
			// loop or a TTL-shifted plane; treat the transition as a gap and
			// do not draw an edge back into the path.
			looped := false
			for back := 0; back < ttl-1; back++ {
				if pa.Hops[back] == "" {
					continue
				}
				if nodeOfDev(p.deviceOf(pa.Hops[back])) == node {
					looped = true
					break
				}
			}
			if looped {
				silent++
				continue
			}
			k := key{prevNode, node}
			l := agg[k]
			if l == nil {
				l = &FLink{From: prevNode, To: node, FromLevel: level[prevNode], ToLevel: level[node]}
				agg[k] = l
			}
			l.Samples++
			l.Flows++
			// Detect the gap from the levels themselves: a transition that
			// jumps more than one level crosses routers that never answered.
			if level[node]-level[prevNode] > 1 {
				l.Skipped = level[node] - level[prevNode] - 1
			}
			if mixedHop(pa.FlowKey, ttl) || mixedHop(pa.FlowKey, ttl-1) {
				// The hop identity was not stable within this flow, so the
				// pair is an inference, not an observation.
				if l.Skipped < 1 {
					l.Skipped = 1
				}
			}
			if pa.RTT[ttl] > 0 {
				rtts[k] = append(rtts[k], pa.RTT[ttl])
			}
			prevNode = node
			prevDev = dev
			silent = 0
		}
		_ = prevDev
	}
	outCount := map[string]int{}
	for _, l := range agg {
		outCount[l.From]++
	}
	var out []FLink
	var branches []Branch
	for k, l := range agg {
		l.Width = outCount[l.From]
		if vs := rtts[k]; len(vs) > 0 {
			sort.Float64s(vs)
			l.MinRTTMs = vs[0]
			l.MaxRTTMs = vs[len(vs)-1]
			l.MedRTTMs = vs[len(vs)/2]
		}
		out = append(out, *l)
	}
	// Prune splice edges that short-circuit a visible chain.  When a silent
	// hop hides between A and B, the observed A->B transition is marked with
	// Skipped>0.  If A can also reach B through a chain of fully visible
	// transitions, the silent splice is not evidence of a direct link; drop
	// it and let the visible chain carry the path.  This is exactly the false
	// link a naive traceroute draws.
	out = pruneSplices(out, level)
	sort.Slice(out, func(i, j int) bool {
		if out[i].FromLevel != out[j].FromLevel {
			return out[i].FromLevel < out[j].FromLevel
		}
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	// Branch table: for every fork, each outgoing edge with width, share and
	// delay relative to the fastest sibling.
	byFrom := map[string][]FLink{}
	for _, l := range out {
		byFrom[l.From] = append(byFrom[l.From], l)
	}
	var forkIDs []string
	for id, ls := range byFrom {
		if len(ls) > 1 {
			forkIDs = append(forkIDs, id)
		}
	}
	sort.Strings(forkIDs)
	for _, id := range forkIDs {
		ls := byFrom[id]
		total := 0
		minRTT := 0.0
		for _, l := range ls {
			total += l.Samples
			if l.MinRTTMs > 0 && (minRTT == 0 || l.MinRTTMs < minRTT) {
				minRTT = l.MinRTTMs
			}
		}
		for _, l := range ls {
			share := 0.0
			if total > 0 {
				share = float64(l.Samples) / float64(total)
			}
			branches = append(branches, Branch{
				Fork: id, To: l.To, Width: l.Width, Samples: l.Samples,
				Share: share, MinRTTMs: l.MinRTTMs, MedRTTMs: l.MedRTTMs,
				ExtraRTTMs: l.MinRTTMs - minRTT, Skipped: l.Skipped,
			})
		}
	}
	return out, branches
}

func trimPrefix(s, p string) string {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}

var _ = sim.KindRouter

// pruneSplices removes same-level short-circuits created by silent hops when a
// visible chain of edges already connects the same pair.
func pruneSplices(links []FLink, level map[string]int) []FLink {
	adj := map[string][]string{}
	for _, l := range links {
		if l.Skipped == 0 {
			adj[l.From] = append(adj[l.From], l.To)
		}
	}
	reach := func(from, to string) bool {
		seen := map[string]bool{from: true}
		stack := []string{from}
		for len(stack) > 0 {
			x := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, y := range adj[x] {
				if y == to {
					return true
				}
				if !seen[y] {
					seen[y] = true
					stack = append(stack, y)
				}
			}
		}
		return false
	}
	out := links[:0:0]
	for _, l := range links {
		if l.Skipped > 0 && reach(l.From, l.To) {
			continue
		}
		out = append(out, l)
	}
	return out
}

// offPathNodes returns the nodes that exist only because a destination sweep
// reached them; they are reported for evidence but excluded from this
// destination's graph.
func (p *prober) offPathNodes(nodes []FNode) []string {
	var out []string
	for _, n := range nodes {
		if n.ID == "src" {
			continue
		}
		dev := p.deviceOf(n.Label)
		if dev == "" {
			continue
		}
		if p.onPathDev[dev] {
			continue
		}
		// A device with at least one address that answered a probe to this
		// destination is on-path even if the representative address came from
		// a sweep.
		onPath := false
		for _, a := range n.Addrs {
			if p.onPathAddr[a] {
				onPath = true
			}
		}
		if !onPath {
			out = append(out, n.ID)
		}
	}
	return out
}
