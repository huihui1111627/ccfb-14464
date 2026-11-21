package sim

import (
	"fmt"
	"net/netip"
)

// Topology builder helpers for the built-in scenarios.

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

func hostRoute() *Route {
	return &Route{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{{Iface: "eth0", Weight: 1}}}
}

func route(prefix string, hops ...NextHop) *Route {
	return &Route{Prefix: mustPrefix(prefix), NextHops: hops}
}

func nh(ifc string, w int) NextHop { return NextHop{Iface: ifc, Weight: w} }

// Scenario names the built-in networks.
type Scenario struct {
	Name string
	Sim  *Sim
	Desc string
	// Src is a host address the prober probes from.
	Src string
	// Dest is the endpoint the prober targets.
	Dest string
}

// ScenarioList returns all built-in scenarios.
func ScenarioList() []string {
	return []string{"diamond", "multitier", "quirks", "stress", "random"}
}

// LoadScenario builds one of the built-in networks.
func LoadScenario(name string, seed int64) (*Scenario, error) {
	switch name {
	case "diamond":
		return diamond(seed), nil
	case "multitier":
		return multitier(seed), nil
	case "quirks":
		return quirks(seed), nil
	case "stress":
		return stress(seed), nil
	case "random":
		return RandomScenario(seed), nil
	}
	return nil, fmt.Errorf("unknown scenario %q (have %v)", name, ScenarioList())
}

// diamond is the classic load-balanced diamond:
//
//	P -- R0 --+-- R1a --+-- R2 -- D
//	           +-- R1b --+
//
// R0 spreads per flow, R1a/R1b are single paths, R2 merges.  R1b is rate
// limited; R2 answers from a pool of loopbacks.
func diamond(seed int64) *Scenario {
	s := New(Config{Seed: seed, ProbeIntervalMS: 15})
	s.AddNode(&Node{
		ID: "P", Name: "10.0.0.1", Kind: KindHost,
		Ifaces: map[string]*Interface{"eth0": {Name: "eth0", Addr: "10.0.0.1", PeerNode: "R0", PeerIface: "e0", DelayMs: 0.2}},
		Order:  []string{"eth0"},
		Routes: []*Route{hostRoute()},
	})
	s.AddNode(&Node{
		ID: "R0", Name: "10.0.1.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.0.1.1", PeerNode: "P", PeerIface: "eth0", DelayMs: 0.2},
			"e1": {Name: "e1", Addr: "10.0.1.2", PeerNode: "R1a", PeerIface: "e0", DelayMs: 3.1},
			"e2": {Name: "e2", Addr: "10.0.1.3", PeerNode: "R1b", PeerIface: "e0", DelayMs: 7.4},
		},
		Order:     []string{"e0", "e1", "e2"},
		Loopbacks: []string{"10.0.1.254"},
		LB:        LBFlow,
		Fields:    []HashField{FieldSrcIP, FieldSrcPort, FieldDstPort, FieldProto},
		Routes:    []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{nh("e1", 1), nh("e2", 1)}}},
		IPIDMode:  IPIDGlobal,
	})
	mkMid := func(id, a0, a1 string, peerDelay, rate float64, silent bool) *Node {
		return &Node{
			ID: id, Name: a0, Kind: KindRouter,
			Ifaces: map[string]*Interface{
				"e0": {Name: "e0", Addr: a0, PeerNode: "R0", PeerIface: ifcFor(id), DelayMs: 0.2},
				"e1": {Name: "e1", Addr: a1, PeerNode: "R2", PeerIface: ifcFor(id), DelayMs: peerDelay},
			},
			Order:        []string{"e0", "e1"},
			Loopbacks:    []string{trimLast(a0) + ".254"},
			ReplyMode:    ReplyIngress,
			ReplyRate:    rate,
			Silent:       silent,
			IPIDMode:     IPIDGlobal,
			Routes:       []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{nh("e1", 1)}}},
			TTLDecrement: 1,
		}
	}
	s.AddNode(mkMid("R1a", "10.0.2.1", "10.0.2.2", 1.7, 0, false))
	s.AddNode(mkMid("R1b", "10.0.3.1", "10.0.3.2", 2.2, 60, false))
	s.AddNode(&Node{
		ID: "R2", Name: "10.0.4.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.0.4.1", PeerNode: "R1a", PeerIface: "e1", DelayMs: 1.7},
			"e1": {Name: "e1", Addr: "10.0.4.2", PeerNode: "R1b", PeerIface: "e1", DelayMs: 2.2},
			"e2": {Name: "e2", Addr: "10.0.4.3", PeerNode: "D", PeerIface: "eth0", DelayMs: 0.3},
		},
		Order:     []string{"e0", "e1", "e2"},
		Loopbacks: []string{"10.0.4.101", "10.0.4.102", "10.0.4.103"},
		ReplyMode: ReplyPool,
		IPIDMode:  IPIDGlobal,
		Routes:    []*Route{{Prefix: mustPrefix("192.168.0.0/16"), NextHops: []NextHop{nh("e2", 1)}}},
	})
	s.AddNode(&Node{
		ID: "D", Name: "192.168.10.9", Kind: KindHost,
		Ifaces: map[string]*Interface{"eth0": {Name: "eth0", Addr: "192.168.10.9", PeerNode: "R2", PeerIface: "e2", DelayMs: 0.3}},
		Order:  []string{"eth0"},
		Routes: []*Route{hostRoute()},
	})
	return &Scenario{Name: "diamond", Sim: s, Src: "10.0.0.1", Dest: "192.168.10.9",
		Desc: "two-path diamond with flow ECMP, a rate-limited branch and pooled reply addresses"}
}

func ifcFor(id string) string {
	if id == "R1a" {
		return "e0"
	}
	return "e1"
}

// multitier is a three-tier topology that exercises destination-based and
// per-packet balancing at different layers.
//
//	P - R0 -+ - R1a -+ - R2 -+ - R3 - D
//	        + - R1b -+        + - R4 - D
//
// R0 balances per destination, R1a/R1b per packet, R2 per flow.
func multitier(seed int64) *Scenario {
	s := New(Config{Seed: seed, ProbeIntervalMS: 15})
	host := func(id, addr, peer string, peerIfc string, d float64) *Node {
		return &Node{
			ID: id, Name: addr, Kind: KindHost,
			Ifaces: map[string]*Interface{"eth0": {Name: "eth0", Addr: addr, PeerNode: peer, PeerIface: peerIfc, DelayMs: d}},
			Order:  []string{"eth0"},
			Routes: []*Route{hostRoute()},
		}
	}
	rtr := func(id, addr string, peerNode, peerIfc string, loopbacks []string, lb LBMode, fields []HashField, routes []*Route) *Node {
		return &Node{
			ID: id, Name: addr, Kind: KindRouter,
			Ifaces:    map[string]*Interface{"e0": {Name: "e0", Addr: addr, PeerNode: peerNode, PeerIface: peerIfc, DelayMs: 0.5}},
			Order:     []string{"e0"},
			Loopbacks: loopbacks, LB: lb, Fields: fields, Routes: routes,
			IPIDMode: IPIDGlobal, ReplyMode: ReplyIngress,
		}
	}
	_ = rtr
	s.AddNode(host("P", "10.10.0.1", "R0", "e0", 0.2))
	s.AddNode(&Node{
		ID: "R0", Name: "10.10.1.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.10.1.1", PeerNode: "P", PeerIface: "eth0", DelayMs: 0.2},
			"e1": {Name: "e1", Addr: "10.10.1.2", PeerNode: "R1a", PeerIface: "e0", DelayMs: 2.0},
			"e2": {Name: "e2", Addr: "10.10.1.3", PeerNode: "R1b", PeerIface: "e0", DelayMs: 5.0},
		},
		Order:     []string{"e0", "e1", "e2"},
		Loopbacks: []string{"10.10.1.100"},
		LB:        LBDest,
		ReplyMode: ReplyIngress, IPIDMode: IPIDGlobal,
		Routes: []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{nh("e1", 1), nh("e2", 1)}}},
	})
	s.AddNode(&Node{
		ID: "R1a", Name: "10.10.2.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.10.2.1", PeerNode: "R0", PeerIface: "e1", DelayMs: 2.0},
			"e1": {Name: "e1", Addr: "10.10.2.2", PeerNode: "R2", PeerIface: "e0", DelayMs: 1.0},
		},
		Order: []string{"e0", "e1"}, Loopbacks: []string{"10.10.2.100"},
		LB: LBPacket, ReplyMode: ReplyIngress, IPIDMode: IPIDGlobal,
		Routes: []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{nh("e1", 1)}}},
	})
	// R1b is a hidden hop: it does not decrement TTL and does not answer.
	s.AddNode(&Node{
		ID: "R1b", Name: "10.10.3.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.10.3.1", PeerNode: "R0", PeerIface: "e2", DelayMs: 5.0},
			"e1": {Name: "e1", Addr: "10.10.3.2", PeerNode: "R2", PeerIface: "e1", DelayMs: 1.5},
		},
		Order: []string{"e0", "e1"}, Loopbacks: []string{"10.10.3.100"},
		Silent: true, TTLDecrement: 0, ReplyMode: ReplyIngress, IPIDMode: IPIDGlobal,
		Routes: []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{nh("e1", 1)}}},
	})
	s.AddNode(&Node{
		ID: "R2", Name: "10.10.4.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.10.4.1", PeerNode: "R1a", PeerIface: "e1", DelayMs: 1.0},
			"e1": {Name: "e1", Addr: "10.10.4.2", PeerNode: "R1b", PeerIface: "e1", DelayMs: 1.5},
			"e2": {Name: "e2", Addr: "10.10.4.3", PeerNode: "R3", PeerIface: "e0", DelayMs: 3.0},
			"e3": {Name: "e3", Addr: "10.10.4.4", PeerNode: "R4", PeerIface: "e0", DelayMs: 9.0},
		},
		Order:     []string{"e0", "e1", "e2", "e3"},
		Loopbacks: []string{"10.10.4.100"},
		LB:        LBFlow, Fields: []HashField{FieldSrcIP, FieldSrcPort, FieldDstPort, FieldProto},
		ReplyMode: ReplyIngress, IPIDMode: IPIDGlobal,
		Routes: []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{nh("e2", 1), nh("e3", 1)}}},
	})
	s.AddNode(&Node{
		ID: "R3", Name: "10.10.5.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.10.5.1", PeerNode: "R2", PeerIface: "e2", DelayMs: 3.0},
			"e1": {Name: "e1", Addr: "10.10.5.2", PeerNode: "D", PeerIface: "eth0", DelayMs: 0.4},
		},
		Order: []string{"e0", "e1"}, Loopbacks: []string{"10.10.5.100"},
		ReplyMode: ReplyIngress, IPIDMode: IPIDGlobal,
		Routes: []*Route{{Prefix: mustPrefix("203.0.113.0/24"), NextHops: []NextHop{nh("e1", 1)}}},
	})
	s.AddNode(&Node{
		ID: "R4", Name: "10.10.6.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.10.6.1", PeerNode: "R2", PeerIface: "e3", DelayMs: 9.0},
			"e1": {Name: "e1", Addr: "10.10.6.2", PeerNode: "D", PeerIface: "eth1", DelayMs: 0.6},
		},
		Order: []string{"e0", "e1"}, Loopbacks: []string{"10.10.6.100"},
		ReplyMode: ReplyIngress, IPIDMode: IPIDGlobal,
		Routes: []*Route{{Prefix: mustPrefix("203.0.113.0/24"), NextHops: []NextHop{nh("e1", 1)}}},
	})
	s.AddNode(&Node{
		ID: "D", Name: "203.0.113.50", Kind: KindHost,
		Ifaces: map[string]*Interface{
			"eth0": {Name: "eth0", Addr: "203.0.113.50", PeerNode: "R3", PeerIface: "e1", DelayMs: 0.4},
			"eth1": {Name: "eth1", Addr: "203.0.113.51", PeerNode: "R4", PeerIface: "e1", DelayMs: 0.6},
		},
		Order:  []string{"eth0", "eth1"},
		Routes: []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{nh("eth0", 1)}}},
	})
	return &Scenario{Name: "multitier", Sim: s, Src: "10.10.0.1", Dest: "203.0.113.50",
		Desc: "three-tier topology with destination ECMP at the edge, packet ECMP in the core and a silent TTL-hiding router"}
}

// quirks is a topology whose routers misbehave in the ways that fool classic
// traceroute: silent hops, rate limits, non-standard TTL, per-address IP-ID,
// random IP-ID and asymmetric return paths.
func quirks(seed int64) *Scenario {
	s := New(Config{Seed: seed, ProbeIntervalMS: 15})
	s.AddNode(&Node{
		ID: "P", Name: "10.20.0.1", Kind: KindHost,
		Ifaces: map[string]*Interface{"eth0": {Name: "eth0", Addr: "10.20.0.1", PeerNode: "R0", PeerIface: "e0", DelayMs: 0.2}},
		Order:  []string{"eth0"}, Routes: []*Route{hostRoute()},
	})
	// R0: silent.  It decrements TTL normally but never answers, so its hop
	// disappears entirely from traceroute.
	s.AddNode(&Node{
		ID: "R0", Name: "10.20.1.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.20.1.1", PeerNode: "P", PeerIface: "eth0", DelayMs: 0.2},
			"e1": {Name: "e1", Addr: "10.20.1.2", PeerNode: "R1", PeerIface: "e0", DelayMs: 1.3},
		},
		Order: []string{"e0", "e1"}, Loopbacks: []string{"10.20.1.254"},
		Silent: true, IPIDMode: IPIDZero,
		Routes: []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{nh("e1", 1)}}},
	})
	// R1: replies from a pool with per-address IP-ID counters and a random
	// outer TTL.  Slow reply rate.
	s.AddNode(&Node{
		ID: "R1", Name: "10.20.2.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.20.2.1", PeerNode: "R0", PeerIface: "e1", DelayMs: 1.3},
			"e1": {Name: "e1", Addr: "10.20.2.2", PeerNode: "R2", PeerIface: "e0", DelayMs: 2.0},
			"e2": {Name: "e2", Addr: "10.20.2.3", PeerNode: "R3", PeerIface: "e0", DelayMs: 6.0},
		},
		Order:     []string{"e0", "e1", "e2"},
		Loopbacks: []string{"10.20.2.101", "10.20.2.102"},
		ReplyMode: ReplyPool, IPIDMode: IPIDPerAddr, OuterTTL: OuterTTLRandom,
		ReplyRate: 3, ReplyBurst: 1,
		LB: LBFlow, Fields: []HashField{FieldSrcPort, FieldDstPort, FieldProto},
		Routes: []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{nh("e1", 1), nh("e2", 1)}}},
	})
	// R2: decrements TTL by 2 (hides a hop's worth of distance) and answers
	// with a fixed outer TTL of 255.
	s.AddNode(&Node{
		ID: "R2", Name: "10.20.3.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.20.3.1", PeerNode: "R1", PeerIface: "e1", DelayMs: 2.0},
			"e1": {Name: "e1", Addr: "10.20.3.2", PeerNode: "R4", PeerIface: "e0", DelayMs: 1.1},
		},
		Order: []string{"e0", "e1"}, Loopbacks: []string{"10.20.3.254"},
		TTLDecrement: 2, OuterTTL: OuterTTLFixed255, IPIDMode: IPIDRandom,
		Routes: []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{nh("e1", 1)}}},
	})
	// R3: a dead-end branch that never decrements TTL (fully invisible) and
	// leads back to R1's other port: a physical loop, not a path to D.
	s.AddNode(&Node{
		ID: "R3", Name: "10.20.4.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.20.4.1", PeerNode: "R1", PeerIface: "e2", DelayMs: 6.0},
			"e1": {Name: "e1", Addr: "10.20.4.2", PeerNode: "R5", PeerIface: "e0", DelayMs: 4.0},
		},
		Order: []string{"e0", "e1"}, Loopbacks: []string{"10.20.4.254"},
		Silent: true, TTLDecrement: 0, IPIDMode: IPIDZero,
		Routes: []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{nh("e1", 1)}}},
	})
	s.AddNode(&Node{
		ID: "R5", Name: "10.20.5.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.20.5.1", PeerNode: "R3", PeerIface: "e1", DelayMs: 4.0},
			"e1": {Name: "e1", Addr: "10.20.5.2", PeerNode: "D", PeerIface: "eth1", DelayMs: 0.2},
		},
		Order: []string{"e0", "e1"}, Loopbacks: []string{"10.20.5.254"},
		ReplyMode: ReplyHighest, IPIDMode: IPIDGlobal,
		Routes: []*Route{{Prefix: mustPrefix("198.51.100.0/24"), NextHops: []NextHop{nh("e1", 1)}}},
	})
	s.AddNode(&Node{
		ID: "R4", Name: "10.20.6.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.20.6.1", PeerNode: "R2", PeerIface: "e1", DelayMs: 1.1},
			"e1": {Name: "e1", Addr: "10.20.6.2", PeerNode: "D", PeerIface: "eth0", DelayMs: 0.5},
		},
		Order: []string{"e0", "e1"}, Loopbacks: []string{"10.20.6.254"},
		ReplyMode: ReplyIngress, IPIDMode: IPIDGlobal,
		Routes: []*Route{{Prefix: mustPrefix("198.51.100.0/24"), NextHops: []NextHop{nh("e1", 1)}}},
	})
	s.AddNode(&Node{
		ID: "D", Name: "198.51.100.7", Kind: KindHost,
		Ifaces: map[string]*Interface{
			"eth0": {Name: "eth0", Addr: "198.51.100.7", PeerNode: "R4", PeerIface: "e1", DelayMs: 0.5},
			"eth1": {Name: "eth1", Addr: "198.51.100.8", PeerNode: "R5", PeerIface: "e1", DelayMs: 0.2},
		},
		Order:  []string{"eth0", "eth1"},
		Routes: []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{nh("eth0", 1)}}},
	})
	return &Scenario{Name: "quirks", Sim: s, Src: "10.20.0.1", Dest: "198.51.100.7",
		Desc: "misbehaving routers: silent, rate-limited, TTL-hiding, random IP-ID, asymmetric returns"}
}

// stress has deeper fan-out and weighted links, to exercise the stopping rule.
func stress(seed int64) *Scenario {
	s := New(Config{Seed: seed, ProbeIntervalMS: 15})
	s.AddNode(&Node{
		ID: "P", Name: "10.30.0.1", Kind: KindHost,
		Ifaces: map[string]*Interface{"eth0": {Name: "eth0", Addr: "10.30.0.1", PeerNode: "R0", PeerIface: "e0", DelayMs: 0.2}},
		Order:  []string{"eth0"}, Routes: []*Route{hostRoute()},
	})
	s.AddNode(&Node{
		ID: "R0", Name: "10.30.1.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.30.1.1", PeerNode: "P", PeerIface: "eth0", DelayMs: 0.2},
			"e1": {Name: "e1", Addr: "10.30.1.2", PeerNode: "A", PeerIface: "e0", DelayMs: 1.0},
			"e2": {Name: "e2", Addr: "10.30.1.3", PeerNode: "B", PeerIface: "e0", DelayMs: 2.0},
			"e3": {Name: "e3", Addr: "10.30.1.4", PeerNode: "C", PeerIface: "e0", DelayMs: 3.0},
			"e4": {Name: "e4", Addr: "10.30.1.5", PeerNode: "D2", PeerIface: "e0", DelayMs: 4.0},
		},
		Order: []string{"e0", "e1", "e2", "e3", "e4"}, Loopbacks: []string{"10.30.1.254"},
		LB: LBFlow, Fields: []HashField{FieldSrcIP, FieldSrcPort, FieldDstPort, FieldProto, FieldTOS},
		IPIDMode: IPIDGlobal, ReplyMode: ReplyIngress,
		Routes: []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{
			nh("e1", 3), nh("e2", 2), nh("e3", 1), nh("e4", 1),
		}}},
	})
	mkBranch := func(id, addr string, delay float64) *Node {
		return &Node{
			ID: id, Name: addr, Kind: KindRouter,
			Ifaces: map[string]*Interface{
				"e0": {Name: "e0", Addr: addr, PeerNode: "R0", PeerIface: branchPort(id), DelayMs: delay},
				"e1": {Name: "e1", Addr: branchAddr(addr, id), PeerNode: "M", PeerIface: mPort(id), DelayMs: 1.0},
			},
			Order: []string{"e0", "e1"}, Loopbacks: []string{trimLast(addr) + ".254"},
			IPIDMode: IPIDGlobal, ReplyMode: ReplyIngress,
			Routes: []*Route{{Prefix: mustPrefix("0.0.0.0/0"), NextHops: []NextHop{nh("e1", 1)}}},
		}
	}
	s.AddNode(mkBranch("A", "10.30.2.1", 1.0))
	s.AddNode(mkBranch("B", "10.30.3.1", 2.0))
	s.AddNode(mkBranch("C", "10.30.4.1", 3.0))
	s.AddNode(mkBranch("D2", "10.30.5.1", 4.0))
	s.AddNode(&Node{
		ID: "M", Name: "10.30.9.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.30.9.1", PeerNode: "A", PeerIface: "e1", DelayMs: 1.0},
			"e1": {Name: "e1", Addr: "10.30.9.2", PeerNode: "B", PeerIface: "e1", DelayMs: 1.0},
			"e2": {Name: "e2", Addr: "10.30.9.3", PeerNode: "C", PeerIface: "e1", DelayMs: 1.0},
			"e3": {Name: "e3", Addr: "10.30.9.4", PeerNode: "D2", PeerIface: "e1", DelayMs: 1.0},
			"e4": {Name: "e4", Addr: "10.30.9.5", PeerNode: "X", PeerIface: "e0", DelayMs: 5.0},
		},
		Order: []string{"e0", "e1", "e2", "e3", "e4"}, Loopbacks: []string{"10.30.9.254"},
		ReplyMode: ReplyPool, IPIDMode: IPIDGlobal,
		Routes: []*Route{{Prefix: mustPrefix("172.16.0.0/12"), NextHops: []NextHop{nh("e4", 1)}}},
	})
	s.AddNode(&Node{
		ID: "X", Name: "10.30.10.1", Kind: KindRouter,
		Ifaces: map[string]*Interface{
			"e0": {Name: "e0", Addr: "10.30.10.1", PeerNode: "M", PeerIface: "e4", DelayMs: 5.0},
			"e1": {Name: "e1", Addr: "10.30.10.2", PeerNode: "T", PeerIface: "eth0", DelayMs: 0.4},
		},
		Order: []string{"e0", "e1"}, Loopbacks: []string{"10.30.10.254"},
		ReplyMode: ReplyIngress, IPIDMode: IPIDGlobal,
		Routes: []*Route{{Prefix: mustPrefix("172.16.0.0/12"), NextHops: []NextHop{nh("e1", 1)}}},
	})
	s.AddNode(&Node{
		ID: "T", Name: "172.16.5.5", Kind: KindHost,
		Ifaces: map[string]*Interface{"eth0": {Name: "eth0", Addr: "172.16.5.5", PeerNode: "X", PeerIface: "e1", DelayMs: 0.4}},
		Order:  []string{"eth0"}, Routes: []*Route{hostRoute()},
	})
	return &Scenario{Name: "stress", Sim: s, Src: "10.30.0.1", Dest: "172.16.5.5",
		Desc: "wide weighted fan-out with five hash fields, distinct branch delays"}
}

func trimLast(a string) string {
	for i := len(a) - 1; i >= 0; i-- {
		if a[i] == '.' {
			return a[:i]
		}
	}
	return a
}

func branchPort(id string) string {
	switch id {
	case "A":
		return "e1"
	case "B":
		return "e2"
	case "C":
		return "e3"
	}
	return "e4"
}

func branchAddr(base, id string) string {
	n := map[string]string{"A": "10.30.2.2", "B": "10.30.3.2", "C": "10.30.4.2", "D2": "10.30.5.2"}
	return n[id]
}

func mPort(id string) string {
	switch id {
	case "A":
		return "e0"
	case "B":
		return "e1"
	case "C":
		return "e2"
	}
	return "e3"
}
