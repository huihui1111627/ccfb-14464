// Package sim implements a packet-level network simulator with routers that
// exhibit the behaviours real devices show when probed with traceroute-style
// packets: per-flow / per-packet / per-destination load balancing, replies
// from different interface addresses, monotonically increasing IP-ID
// counters, ICMP rate limiting, silent hops, non-standard TTL handling and
// asymmetric return paths.
//
// The simulator is the "network under test".  The prober in package probe is
// only allowed to observe the public Reply values produced by Sim.Send.
// Everything else (real topology, hash fields, per-node behaviour) is ground
// truth that the prober must rediscover.
package sim

import (
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
)

// Kind distinguishes transit routers from probe endpoints.
type Kind int

const (
	KindRouter Kind = iota
	KindHost
)

// LBMode is the next-hop selection policy of a router (or of one route).
type LBMode int

const (
	LBInherit LBMode = iota // use the node default
	LBSingle                // one next hop, no choice
	LBFlow                  // hash over a subset of the flow header
	LBPacket                // choice per packet, header independent
	LBDest                  // hash over the destination prefix only
)

func (m LBMode) String() string {
	switch m {
	case LBFlow:
		return "flow"
	case LBPacket:
		return "packet"
	case LBDest:
		return "destination"
	case LBSingle:
		return "single"
	default:
		return "inherit"
	}
}

// HashField names a header field a router may include in its load-balancing
// hash.  These are exactly the fields a prober can vary.
type HashField int

const (
	FieldSrcIP HashField = iota
	FieldDstIP
	FieldSrcPort
	FieldDstPort
	FieldProto
	FieldTOS
	FieldIPID
	FieldFlowLabel
)

func (f HashField) String() string {
	switch f {
	case FieldSrcIP:
		return "src_ip"
	case FieldDstIP:
		return "dst_ip"
	case FieldSrcPort:
		return "src_port"
	case FieldDstPort:
		return "dst_port"
	case FieldProto:
		return "proto"
	case FieldTOS:
		return "tos"
	case FieldIPID:
		return "ip_id"
	case FieldFlowLabel:
		return "flow_label"
	}
	return "unknown"
}

// AllHashFields is the candidate set a prober sweeps during field discovery.
var AllHashFields = []HashField{
	FieldSrcIP, FieldDstIP, FieldSrcPort, FieldDstPort,
	FieldProto, FieldTOS, FieldIPID, FieldFlowLabel,
}

// ReplyMode selects the source address a router uses for its ICMP replies.
type ReplyMode int

const (
	ReplyIngress    ReplyMode = iota // address of the interface the probe arrived on
	ReplyPool                        // round-robin over ingress + loopbacks
	ReplyLoopbackRR                  // round-robin over loopbacks only
	ReplyHighest                     // highest loopback address
)

// IPIDMode describes how a device fills the IP identification field of the
// packets (ICMP replies) it originates.
type IPIDMode int

const (
	IPIDGlobal  IPIDMode = iota // one counter shared by all interfaces of the device
	IPIDPerAddr                 // one counter per interface address
	IPIDRandom                  // random value per packet
	IPIDZero                    // always zero (many modern stacks)
)

// OuterTTLMode describes the TTL a device puts in the outer IP header of an
// ICMP reply.  Real devices are inconsistent here; tools that infer hop
// distance from the reply TTL draw wrong links.
type OuterTTLMode int

const (
	OuterTTLNormal OuterTTLMode = iota // 64 - return hops
	OuterTTLFixed255
	OuterTTLRandom
	OuterTTLZero
)

// Interface is one directed link endpoint on a node.  DelayMs is the one-way
// delay of the link leaving this interface.
type Interface struct {
	Name      string
	Addr      string
	PeerNode  string
	PeerIface string
	DelayMs   float64
}

// NextHop names an outgoing interface and its ECMP weight.
type NextHop struct {
	Iface  string
	Weight int
}

// Route is a forwarding entry.  Prefix covers destination addresses.  A
// route may override the node-wide LB policy and hash field set.
type Route struct {
	Prefix   netip.Prefix
	NextHops []NextHop
	LB       LBMode
	Fields   []HashField
	DestBits int // prefix length used by LBDest, default 24
}

// Node is a router or endpoint host.
type Node struct {
	ID   string
	Name string
	Kind Kind

	Ifaces map[string]*Interface
	Order  []string
	Routes []*Route

	// Router behaviour.
	Loopbacks    []string
	ReplyMode    ReplyMode
	LB           LBMode
	Fields       []HashField
	Silent       bool
	ReplyRate    float64 // ICMP time-exceeded replies per second; 0 = unlimited
	ReplyBurst   int
	TTLDecrement int // how much this node subtracts from the TTL; 1 = normal, 0 = hidden
	IPIDMode     IPIDMode
	OuterTTL     OuterTTLMode

	// AliasSide marks the interfaces the device uses when it is the last
	// router in front of the destination (its "destination-facing" side).
	// Real networks number these differently from the uplink and the prober
	// must not assume one address equals one device.
	Facing map[string]bool

	// Runtime state.
	ipid     uint32
	perAddr  map[string]uint32
	tokens   float64
	lastFill float64 // seconds on the simulation clock
	packetRR uint64
	replyRR  uint64
	rng      *rand.Rand
}

// Probe is a traceroute-style packet.  Fields a router hashes over are all
// visible here and can be varied independently by the prober.
type Probe struct {
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Proto     uint8
	TOS       uint8
	IPID      uint16
	FlowLabel uint32
	TTL       int
}

// ReplyKind classifies the response the network produced.
type ReplyKind int

const (
	ReplyNone ReplyKind = iota // packet dropped / no answer
	ReplyTimeExceeded
	ReplyEcho
)

// Reply is everything the prober is allowed to see.  SrcNode is deliberately
// NOT exposed here; alias resolution has to work from addresses and IP-ID
// behaviour only.  (The simulator keeps the binding internally for ground
// truth.)
type Reply struct {
	Kind     ReplyKind
	SrcAddr  string
	IPID     uint16
	OuterTTL int
	RTTMs    float64
}

// Config holds simulation-wide knobs.
type Config struct {
	ProbeIntervalMS float64 // simulated wall clock between probes
	Seed            int64
}

// Sim is one simulated network instance.
type Sim struct {
	Cfg   Config
	Nodes map[string]*Node
	Order []string

	byAddr map[string]*Node
	hosts  map[string]bool

	now   float64 // seconds
	rng   *rand.Rand
	seqID uint64
}

// New creates an empty simulator.
func New(cfg Config) *Sim {
	if cfg.ProbeIntervalMS <= 0 {
		cfg.ProbeIntervalMS = 2
	}
	seed := cfg.Seed
	if seed == 0 {
		seed = 1
	}
	return &Sim{
		Cfg:    cfg,
		Nodes:  map[string]*Node{},
		byAddr: map[string]*Node{},
		hosts:  map[string]bool{},
		rng:    rand.New(rand.NewSource(seed ^ 0x5bf03635)),
	}
}

// AddNode inserts a node and indexes its addresses.
func (s *Sim) AddNode(n *Node) {
	if n.Ifaces == nil {
		n.Ifaces = map[string]*Interface{}
	}
	if n.Kind == KindRouter {
		if n.TTLDecrement == 0 {
			n.TTLDecrement = 1
		}
	}
	if n.ReplyBurst == 0 {
		n.ReplyBurst = 2
	}
	n.rng = rand.New(rand.NewSource(int64(len(s.Order)+1) * 1013904223))
	// Devices initialise their IP-ID counters at unrelated values, the way
	// real stacks come up.  Two interfaces of one device share a counter and
	// therefore stay close; two unrelated devices drift apart by their base
	// offsets.  That difference is what alias resolution keys on.
	n.ipid = uint32(n.rng.Intn(65536))
	n.perAddr = map[string]uint32{}
	if len(n.Loopbacks) > 0 {
		n.perAddr[n.Loopbacks[0]] = n.ipid
	}
	for i, name := range n.Order {
		if ifc := n.Ifaces[name]; ifc != nil {
			n.perAddr[ifc.Addr] = n.ipid + uint32(i)
		}
	}
	for i, a := range n.Loopbacks {
		if _, ok := n.perAddr[a]; !ok {
			n.perAddr[a] = n.ipid + uint32(i)
		}
	}
	s.Nodes[n.ID] = n
	s.Order = append(s.Order, n.ID)
	s.byAddr[n.Name] = n
	for _, ifc := range n.Ifaces {
		s.byAddr[ifc.Addr] = n
	}
	for _, a := range n.Loopbacks {
		s.byAddr[a] = n
	}
	if n.Kind == KindHost {
		s.hosts[n.Name] = true
	}
}

// NodeByAddr resolves an address to its owning node.
func (s *Sim) NodeByAddr(addr string) *Node { return s.byAddr[addr] }

// HostAddrs returns the addresses of endpoint hosts (useful for CLI config).
func (s *Sim) HostAddrs() []string {
	var out []string
	for _, id := range s.Order {
		n := s.Nodes[id]
		if n.Kind == KindHost {
			out = append(out, n.Name)
			out = append(out, n.Loopbacks...)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Sim) tokenFill(n *Node) {
	if n.ReplyRate <= 0 {
		return
	}
	dt := s.now - n.lastFill
	if dt < 0 {
		dt = 0
	}
	n.tokens += dt * n.ReplyRate
	if max := float64(n.ReplyBurst); n.tokens > max {
		n.tokens = max
	}
	n.lastFill = s.now
}

func (s *Sim) allowReply(n *Node) bool {
	if n.ReplyRate <= 0 {
		return true
	}
	s.tokenFill(n)
	if n.tokens >= 1 {
		n.tokens--
		return true
	}
	return false
}

func (n *Node) nextIPID(addr string) uint16 {
	switch n.IPIDMode {
	case IPIDZero:
		return 0
	case IPIDRandom:
		return uint16(n.rng.Intn(65536))
	case IPIDPerAddr:
		n.perAddr[addr]++
		return uint16(n.perAddr[addr])
	default:
		n.ipid++
		return uint16(n.ipid)
	}
}

// pickNextHop implements the forwarding decision.  The returned interface and
// weight bucket index are deterministic for a given probe and router state.
func (n *Node) routeFor(dst netip.Addr) *Route {
	var best *Route
	for _, r := range n.Routes {
		if r.Prefix.Contains(dst) {
			if best == nil || r.Prefix.Bits() > best.Prefix.Bits() {
				best = r
			}
		}
	}
	return best
}

func (n *Node) pickNextHop(r *Route, p Probe) (string, bool) {
	if len(r.NextHops) == 0 {
		return "", false
	}
	if len(r.NextHops) == 1 {
		return r.NextHops[0].Iface, true
	}
	mode := r.LB
	if mode == LBInherit {
		mode = n.LB
	}
	fields := r.Fields
	if len(fields) == 0 {
		fields = n.Fields
	}
	total := 0
	for _, nh := range r.NextHops {
		w := nh.Weight
		if w <= 0 {
			w = 1
		}
		total += w
	}
	var h uint64
	switch mode {
	case LBPacket:
		// Every packet independently; ignores all header fields.
		n.packetRR++
		h = n.packetRR * 0x9E3779B97F4A7C15
	default:
		if mode == LBDest {
			bits := r.DestBits
			if bits == 0 {
				bits = 32
			}
			pref, err := netip.ParsePrefix(p.DstIP + fmt.Sprintf("/%d", bits))
			if err == nil {
				h = fnvInit()
				h = fnvAddAddr(h, pref.Masked().Addr())
			} else {
				h = fnvInit()
				h = fnvAddStr(h, p.DstIP)
			}
		} else {
			h = fnvInit()
			for _, f := range fields {
				h = fnvAddField(h, f, p)
			}
		}
	}
	idx := int(h % uint64(total))
	acc := 0
	for _, nh := range r.NextHops {
		w := nh.Weight
		if w <= 0 {
			w = 1
		}
		acc += w
		if idx < acc {
			return nh.Iface, true
		}
	}
	return r.NextHops[len(r.NextHops)-1].Iface, true
}

// replyAddr chooses the source address for a time-exceeded reply.  ingress is
// the address of the interface the packet entered through.
func (n *Node) replyAddr(ingress string) string {
	switch n.ReplyMode {
	case ReplyPool:
		pool := append([]string{}, n.Loopbacks...)
		if ingress != "" {
			pool = append(pool, ingress)
		}
		if len(pool) == 0 {
			return ingress
		}
		n.replyRR++
		return pool[n.replyRR%uint64(len(pool))]
	case ReplyLoopbackRR:
		if len(n.Loopbacks) == 0 {
			return ingress
		}
		n.replyRR++
		return n.Loopbacks[n.replyRR%uint64(len(n.Loopbacks))]
	case ReplyHighest:
		if len(n.Loopbacks) == 0 {
			return ingress
		}
		best := n.Loopbacks[0]
		for _, a := range n.Loopbacks[1:] {
			if a > best {
				best = a
			}
		}
		return best
	default:
		return ingress
	}
}
