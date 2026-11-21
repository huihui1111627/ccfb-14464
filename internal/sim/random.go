package sim

import (
	"fmt"
	"math/rand"
)

// RandomScenario builds a seeded layered network with forks and merges and a
// random mixture of router dispositions.  It is the generalisation test: the
// prober sees no hand-tuned structure, only whatever policy the generator
// drew.
//
// Layers are laid out left to right.  Every node in layer i connects to one
// or two nodes in layer i+1 with weights 1..3; the last layer connects to the
// destination.  At least one fork and one merge are forced so the graph has
// the diamond shape the tool must reconstruct.
func RandomScenario(seed int64) *Scenario {
	rng := rand.New(rand.NewSource(seed*2654435761 + 1))
	s := New(Config{Seed: seed, ProbeIntervalMS: 15})

	const srcAddr = "10.40.0.1"
	dstAddr := "203.0.113.9"

	s.AddNode(&Node{
		ID: "P", Name: srcAddr, Kind: KindHost,
		Ifaces: map[string]*Interface{},
	})

	layers := 3 + rng.Intn(2) // 3..4 transit layers
	layerIDs := make([][]string, layers)
	nextLayerSize := func() int {
		n := 1 + rng.Intn(3)
		if n > 3 {
			n = 3
		}
		return n
	}
	var ids []string
	for l := 0; l < layers; l++ {
		n := nextLayerSize()
		if l == 1 {
			n = 2 + rng.Intn(2) // force a fork layer
		}
		for k := 0; k < n; k++ {
			id := fmt.Sprintf("L%dN%d", l, k)
			layerIDs[l] = append(layerIDs[l], id)
			ids = append(ids, id)
		}
	}

	// Every interface gets its own address in the node's block: real routers
	// do not share one address across ports, and alias resolution depends on
	// the prober seeing distinct interface addresses of one device.
	addrOf := func(l, k, ifIdx int) string { return fmt.Sprintf("10.40.%d.%d", l+1, 10+k*20+ifIdx) }
	loOf := func(l, k int) string { return fmt.Sprintf("10.41.%d.%d", l+1, k+1) }

	// Assign dispositions.
	type disp struct {
		lb     LBMode
		fields []HashField
		silent bool
		rate   float64
		ttlDec int
		ipid   IPIDMode
		outer  OuterTTLMode
		reply  ReplyMode
	}
	modes := []LBMode{LBFlow, LBFlow, LBPacket, LBDest, LBSingle}
	fieldsets := [][]HashField{
		{FieldSrcIP, FieldSrcPort, FieldDstPort, FieldProto},
		{FieldSrcPort, FieldDstPort},
		{FieldDstIP},
		{FieldSrcIP, FieldSrcPort, FieldDstPort, FieldProto, FieldTOS},
	}
	// Per-address IP-ID is assigned only to devices that answer from a pool;
	// a single reply address with a per-address counter is just a global
	// counter and would make the two cases indistinguishable by observation.
	_ = modes
	disps := map[string]disp{}
	for _, id := range ids {
		replyMode := []ReplyMode{ReplyIngress, ReplyIngress, ReplyPool, ReplyLoopbackRR, ReplyHighest}[rng.Intn(5)]
		ipid := IPIDMode(0)
		switch rng.Intn(6) {
		case 0, 1, 2:
			ipid = IPIDGlobal
		case 3:
			if replyMode == ReplyIngress || replyMode == ReplyHighest {
				ipid = IPIDGlobal
			} else {
				ipid = IPIDPerAddr
			}
		case 4:
			ipid = IPIDRandom
		case 5:
			ipid = IPIDZero
		}
		d := disp{
			lb:     modes[rng.Intn(len(modes))],
			fields: fieldsets[rng.Intn(len(fieldsets))],
			ttlDec: 1,
			ipid:   ipid,
			outer:  []OuterTTLMode{OuterTTLNormal, OuterTTLNormal, OuterTTLFixed255, OuterTTLRandom}[rng.Intn(4)],
			reply:  replyMode,
		}
		switch rng.Intn(10) {
		case 0:
			d.silent = true
		case 1:
			d.rate = 20 + float64(rng.Intn(60))
		case 2:
			d.ttlDec = 2
		}
		disps[id] = d
	}
	// At least one flow-balanced fork and one packet-balanced fork exists in
	// most draws; force the second layer's first node to flow balancing.
	first := disps[layerIDs[1][0]]
	first.lb = LBFlow
	first.silent = false
	first.fields = []HashField{FieldSrcIP, FieldSrcPort, FieldDstPort, FieldProto}
	disps[layerIDs[1][0]] = first

	nodeByID := map[string]*Node{}
	for l, layer := range layerIDs {
		for k, id := range layer {
			n := &Node{
				ID: id, Name: addrOf(l, k, 0), Kind: KindRouter,
				Ifaces:       map[string]*Interface{},
				Loopbacks:    []string{loOf(l, k)},
				IPIDMode:     disps[id].ipid,
				OuterTTL:     disps[id].outer,
				ReplyMode:    disps[id].reply,
				LB:           disps[id].lb,
				Fields:       disps[id].fields,
				Silent:       disps[id].silent,
				ReplyRate:    disps[id].rate,
				TTLDecrement: disps[id].ttlDec,
			}
			nodeByID[id] = n
			s.AddNode(n)
		}
	}

	layerIdx := map[string][2]int{}
	for l, layer := range layerIDs {
		for k, id := range layer {
			layerIdx[id] = [2]int{l, k}
		}
	}
	linkCount := 0
	addLink := func(a *Node, b *Node, delay float64) {
		an := fmt.Sprintf("e%d", len(a.Order))
		bn := fmt.Sprintf("e%d", len(b.Order))
		a.Order = append(a.Order, an)
		b.Order = append(b.Order, bn)
		aa, ba := a.Name, b.Name
		if li, ok := layerIdx[a.ID]; ok {
			aa = addrOf(li[0], li[1], len(a.Order)-1)
		}
		if li, ok := layerIdx[b.ID]; ok {
			ba = addrOf(li[0], li[1], len(b.Order)-1)
		}
		a.Ifaces[an] = &Interface{Name: an, Addr: aa, PeerNode: b.ID, PeerIface: bn, DelayMs: delay}
		b.Ifaces[bn] = &Interface{Name: bn, Addr: ba, PeerNode: a.ID, PeerIface: an, DelayMs: delay}
		linkCount++
	}
	// Source -> layer 0.  If layer 0 has several nodes, the source fans out.
	for k := range layerIDs[0] {
		addLink(s.Nodes["P"], nodeByID[layerIDs[0][k]], 0.3+0.2*float64(k))
	}
	// Layer to layer: each node gets 1-2 children, chosen to ensure every
	// child has at least one parent and at least one parent has two.
	parentOf := map[string][]string{} // child -> parents
	for l := 0; l < layers-1; l++ {
		parents := layerIDs[l]
		children := layerIDs[l+1]
		for ci, c := range children {
			p := parents[ci%len(parents)]
			parentOf[c] = append(parentOf[c], p)
		}
		for _, p := range parents {
			extra := children[rng.Intn(len(children))]
			found := false
			for _, x := range parentOf[extra] {
				if x == p {
					found = true
				}
			}
			if !found {
				parentOf[extra] = append(parentOf[extra], p)
			}
		}
		for _, c := range children {
			for _, p := range parentOf[c] {
				addLink(nodeByID[p], nodeByID[c], 0.5+float64(rng.Intn(60))/10.0)
			}
		}
	}
	// Last layer -> destination.
	last := layerIDs[layers-1]
	dn := &Node{
		ID: "D", Name: dstAddr, Kind: KindHost,
		Ifaces: map[string]*Interface{}, Order: nil,
	}
	for k, id := range last {
		addLink(nodeByID[id], dn, 0.4+0.2*float64(k))
	}
	s.AddNode(dn)
	// Hosts route out of whichever interface is attached; the direction does
	// not matter for echo replies but the simulator needs a valid one.
	hostRouteAll := func(n *Node) {
		// A host replies from whichever interface the probe arrived on; for
		// the simulator's forwarding model one attachment is enough, and
		// using a single interface keeps reply addressing unambiguous.
		if len(n.Order) == 0 {
			return
		}
		n.Routes = []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{{Iface: n.Order[0], Weight: 1}}}}
	}
	hostRouteAll(s.Nodes["P"])
	hostRouteAll(dn)

	// Forwarding: every router sends everything to all of its neighbours one
	// layer further right; the destination's host route is terminal.
	for l := 0; l < layers; l++ {
		for _, id := range layerIDs[l] {
			n := nodeByID[id]
			var hops []NextHop
			for _, name := range n.Order {
				ifc := n.Ifaces[name]
				peer := s.Nodes[ifc.PeerNode]
				if peer == nil || peer.Kind == KindHost {
					continue
				}
				// Only forward to the next layer, never back.
				if layerOf(peer.ID, layerIDs) <= l {
					continue
				}
				hops = append(hops, NextHop{Iface: name, Weight: 1 + rng.Intn(3)})
			}
			if len(hops) == 0 {
				// Last layer: send to the destination.
				for _, name := range n.Order {
					ifc := n.Ifaces[name]
					if s.Nodes[ifc.PeerNode] != nil && s.Nodes[ifc.PeerNode].Kind == KindHost {
						hops = append(hops, NextHop{Iface: name, Weight: 1})
					}
				}
			}
			n.Routes = []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: hops}}
		}
	}

	return &Scenario{
		Name: "random", Sim: s, Src: srcAddr, Dest: dstAddr,
		Desc: fmt.Sprintf("seeded random layered network (seed %d): %d routers over %d layers, mixed balancing and quirks", seed, len(ids), layers),
	}
}

func layerOf(id string, layers [][]string) int {
	for l, layer := range layers {
		for _, x := range layer {
			if x == id {
				return l
			}
		}
	}
	return 99
}
