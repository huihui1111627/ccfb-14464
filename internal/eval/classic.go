package eval

import "topomap/internal/sim"

// runClassic emulates a naive single-flow traceroute.
//
// One probe per TTL, one flow, no alias resolution: every answering address
// becomes a device of its own, holes are spliced over, and consecutive
// answered TTLs are declared adjacent.  This is the report the operator was
// waving at us.
func runClassic(sc *sim.Scenario, truthDev map[string]bool, addrDev map[string]string) ClassicScore {
	var cs ClassicScore
	base := sim.Probe{SrcIP: sc.Src, DstIP: sc.Dest, SrcPort: 45123, DstPort: 33434, Proto: 17}
	var hops []string
	for ttl := 1; ttl <= 40; ttl++ {
		p := base
		p.TTL = ttl
		rep, _ := sc.Sim.Send(p)
		cs.Probes++
		if rep.Kind == sim.ReplyNone {
			continue
		}
		hops = append(hops, rep.SrcAddr)
		if rep.Kind == sim.ReplyEcho {
			break
		}
	}
	cs.Hops = len(hops)
	cs.Paths = 1

	// Classic maps each address to its own device entry (no alias merging).
	devSet := map[string]bool{}
	for _, a := range hops {
		if a == sc.Src || a == sc.Dest {
			continue
		}
		devSet["iface:"+a] = true
	}
	cs.Devices = len(devSet)

	// Device recall: a truth router counts as found when any of its interface
	// addresses appeared -- classic gets this for free because it sees
	// whatever answered.
	found := 0
	for d := range truthDev {
		n := sc.Sim.Nodes[d]
		ok := false
		for _, name := range n.Order {
			ifc := n.Ifaces[name]
			if ifc == nil {
				continue
			}
			for _, a := range hops {
				if a == ifc.Addr {
					ok = true
				}
			}
		}
		if ok {
			found++
		}
	}
	if len(truthDev) > 0 {
		cs.Recall = float64(found) / float64(len(truthDev))
	}
	if len(devSet) > 0 {
		cs.Precision = float64(found) / float64(len(devSet))
	}
	// False links: consecutive answered hops that are not truly adjacent.
	type edge struct{ a, b string }
	trueEdges := map[edge]bool{}
	for _, id := range sc.Sim.Order {
		n := sc.Sim.Nodes[id]
		for _, name := range n.Order {
			trueEdges[edge{id, n.Ifaces[name].PeerNode}] = true
		}
	}
	for i := 0; i+1 < len(hops); i++ {
		a, b := addrDev[hops[i]], addrDev[hops[i+1]]
		if a == b {
			continue
		}
		if !trueEdges[edge{a, b}] {
			cs.FalseLinks++
		}
	}
	return cs
}
