package probe

import (
	"sort"
)

// buildGraph fuses the per-flow paths into a DAG with forks and merges.
func (p *prober) buildGraph() {
	f := &Fusion{}
	f.Stats.Probes = p.probes
	f.Stats.Rounds = p.rounds
	f.Stats.Flows = len(p.flows)

	// Recompute the device histogram from the final alias clusters before any
	// counting, so estimates and group sizes agree with the graph.
	p.rebuildHopDevs()
	p.computeFlowMultiplicity()
	// Drop devices reached only through off-path destination sweeps: they are
	// real, but they are not part of this destination's paths and must not
	// inflate branch counts.
	offDev := map[string]bool{}
	for _, r := range p.records {
		if r.OffPath && r.ReplyAddr != "" {
			offDev[p.deviceOf(r.ReplyAddr)] = true
		}
	}
	for ttl, m := range p.hopDevs {
		var drop []string
		for d := range m {
			if offDev[d] && !p.onPathDev[d] {
				drop = append(drop, d)
			}
		}
		for _, d := range drop {
			delete(m, d)
		}
		if len(m) == 0 {
			delete(p.hopDevs, ttl)
		}
	}
	// Hop groups: reply addresses per TTL, keyed by device cluster so that
	// several interfaces of one device do not look like several hops.
	ttls := make([]int, 0, len(p.hopAddrs))
	for ttl := range p.hopAddrs {
		ttls = append(ttls, ttl)
	}
	sort.Ints(ttls)
	for _, ttl := range ttls {
		hg := HopGroup{TTL: ttl}
		devCount := map[string]int{}
		for a, c := range p.hopAddrs[ttl] {
			devCount[p.deviceOf(a)] += c
		}
		// Report the most frequently observed address per device as the label.
		devBest := map[string]string{}
		devBestN := map[string]int{}
		for a, c := range p.hopAddrs[ttl] {
			d := p.deviceOf(a)
			if c > devBestN[d] {
				devBestN[d] = c
				devBest[d] = a
			}
		}
		for d := range devCount {
			hg.Devices = append(hg.Devices, d)
			hg.Addrs = append(hg.Addrs, devBest[d])
		}
		sort.Strings(hg.Devices)
		sort.Slice(hg.Addrs, func(i, j int) bool { return p.deviceOf(hg.Addrs[i]) < p.deviceOf(hg.Addrs[j]) })
		f.NGroups = append(f.NGroups, hg)
		f.Estimates = append(f.Estimates, p.estimateHop(ttl))
	}

	p.groupPaths()
	f.Paths = p.mergedGroups
	// Devices reached only through off-path destination sweeps are reported
	// as observations, not as part of this destination's graph.
	p.onPathDev = map[string]bool{}
	for _, pa := range p.paths {
		for _, a := range pa.Hops {
			if a != "" {
				p.onPathDev[p.deviceOf(a)] = true
			}
		}
	}
	f.Nodes = p.nodes()
	f.OffPathDevices = p.offPathNodes(f.Nodes)
	f.Links, f.Branches = p.links(f.Nodes)
	f.Ifaces = p.ifaceNodes
	f.Anomalies = p.anomalies()
	f.Stats.SilentHops, f.Stats.TTLHidingHops, f.Stats.RateLimited, f.Stats.Asymmetric = p.quirkStats()
	p.res.LBPerHop = p.lb
	p.res.Clusters = toClusters(p.clusters)
	for i := range p.res.Clusters {
		if id, ok := p.devToNode[p.res.Clusters[i].ID]; ok {
			p.res.Clusters[i].DeviceID = id
			for _, n := range f.Nodes {
				if n.ID == id {
					p.res.Clusters[i].Level = n.Level
					p.res.Clusters[i].Label = n.Label
				}
			}
		}
	}
	p.res.Graph = f
}

func (p *prober) derefPaths() []Path {
	out := make([]Path, 0, len(p.paths))
	for _, pa := range p.paths {
		out = append(out, *pa)
	}
	return out
}

// computeFlowMultiplicity records, for every flow and TTL, how many distinct
// devices answered.  A value above one means a per-packet balancer sits
// upstream, so hop identity is not stable within that flow.
func (p *prober) computeFlowMultiplicity() {
	p.flowMulti = map[string]map[int]int{}
	seen := map[string]map[int]map[string]bool{}
	for _, r := range p.records {
		if r.ReplyAddr == "" || r.ReplyKind == "none" {
			continue
		}
		// Only probe traffic that belongs to the mapping run for this
		// destination; off-path sweeps describe a different graph.
		if r.FlowGroup != "scan" && r.FlowGroup != "depth" {
			continue
		}
		flowID := r.FlowKey
		if seen[flowID] == nil {
			seen[flowID] = map[int]map[string]bool{}
		}
		if seen[flowID][r.Hop] == nil {
			seen[flowID][r.Hop] = map[string]bool{}
		}
		seen[flowID][r.Hop][p.deviceOf(r.ReplyAddr)] = true
	}
	for f, hops := range seen {
		p.flowMulti[f] = map[int]int{}
		for ttl, set := range hops {
			p.flowMulti[f][ttl] = len(set)
		}
	}
}
