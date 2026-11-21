package sim

import (
	"fmt"
	"net/netip"
	"strings"
)

// HopRec is one forwarding step recorded while a probe travels the network.
// It is ground truth, kept for the evaluator only.
type HopRec struct {
	NodeID  string
	Iface   string // outgoing interface
	PeerID  string
	PeerIfc string
}

// Send delivers a probe into the simulated network and returns the first
// reply it provokes, plus the full forwarding trace (ground truth).
//
// Rules modelled:
//   - Each router subtracts TTLDecrement (normally 1) from the TTL.  A router
//     whose decrement is 0 hides itself from traceroute by not dropping.
//   - A probe whose TTL would reach 0 at a router is dropped there; the router
//     emits ICMP time-exceeded unless it is Silent or rate-limited.  The
//     reply travels back along a per-router return path (asymmetric), so the
//     measured RTT is forward + return, not twice the forward delay.
//   - When the probe reaches a host it produces an echo reply (also subject
//     to the host's reply rate).
func (s *Sim) Send(p Probe) (Reply, []HopRec) {
	// Wall clock advances between probes so ICMP rate-limit token buckets
	// refill the way they would on a real link.
	s.now += s.Cfg.ProbeIntervalMS / 1000.0
	cur := s.byAddr[p.SrcIP]
	if cur == nil {
		// Probes may originate from another address on the source host
		// (source-address variation).  Resolve by longest /24 match.
		cur = s.sourceInSubnet(p.SrcIP)
	}
	if cur == nil {
		return Reply{}, nil
	}
	ifs := p.TTL
	if ifs <= 0 {
		ifs = 64
	}
	dest, err := netip.ParseAddr(p.DstIP)
	if err != nil {
		return Reply{}, nil
	}
	ttl := ifs
	var recs []HopRec
	for steps := 0; steps < 256; steps++ {
		var r *Route
		var iface string
		var ok bool
		if cur.Kind == KindHost {
			// On a host the "route" is the host's attachment.
			r = cur.routeFor(dest)
			if r == nil || len(r.NextHops) == 0 {
				return Reply{}, recs
			}
			iface = r.NextHops[0].Iface
			ok = true
		} else {
			r = cur.routeFor(dest)
			if r == nil {
				return Reply{}, recs
			}
			iface, ok = cur.pickNextHop(r, p)
		}
		if !ok || iface == "" {
			return Reply{}, recs
		}
		link := cur.Ifaces[iface]
		if link == nil {
			return Reply{}, recs
		}
		rec := HopRec{NodeID: cur.ID, Iface: iface, PeerID: link.PeerNode, PeerIfc: link.PeerIface}
		recs = append(recs, rec)

		next := s.Nodes[link.PeerNode]
		if next == nil {
			return Reply{}, recs
		}
		// Forward delay across this link.
		s.now += link.DelayMs / 1000.0

		if next.Kind == KindHost {
			// Probe arrives at the endpoint, but only an address the host
			// actually owns produces an echo; anything else is blackholed.
			if !next.ownsAddr(p.DstIP) {
				return Reply{Kind: ReplyNone}, recs
			}
			if !s.allowReply(next) {
				return Reply{Kind: ReplyNone}, recs
			}
			ret := s.returnPath(next, cur)
			rtt := link.DelayMs + ret
			src := next.Ifaces[link.PeerIface]
			addr := next.Name
			if src != nil {
				addr = src.Addr
			}
			return Reply{
				Kind:     ReplyEcho,
				SrcAddr:  addr,
				IPID:     next.nextIPID(addr),
				OuterTTL: next.outerTTLValue(ret, 64),
				RTTMs:    rtt,
			}, recs
		}

		// Transit router.
		ttl -= next.TTLDecrement
		if ttl <= 0 {
			if next.Silent || !s.allowReply(next) {
				return Reply{Kind: ReplyNone}, recs
			}
			ret := s.returnPath(next, cur)
			// The ingress interface is the one facing the previous node.
			ingress := s.ifaceToward(next, cur.ID)
			addr := next.replyAddr(ingress)
			return Reply{
				Kind:     ReplyTimeExceeded,
				SrcAddr:  addr,
				IPID:     next.nextIPID(addr),
				OuterTTL: next.outerTTLValue(ret, 64),
				RTTMs:    link.DelayMs + ret,
			}, recs
		}
		s.now += 0 // link delay already accounted before TTL check
		cur = next
		if cur.Kind == KindHost {
			continue
		}
	}
	return Reply{}, recs
}

// sourceInSubnet finds the host owning an address in the same /24.
func (s *Sim) sourceInSubnet(addr string) *Node {
	o := octetPrefix(addr)
	if o == "" {
		return nil
	}
	for _, id := range s.Order {
		n := s.Nodes[id]
		if n.Kind != KindHost {
			continue
		}
		for _, a := range n.AllAddrs() {
			if octetPrefix(a) == o {
				return n
			}
		}
	}
	return nil
}

func octetPrefix(a string) string {
	n := 0
	for i := 0; i < len(a); i++ {
		if a[i] == '.' {
			n++
			if n == 3 {
				return a[:i]
			}
		}
	}
	return ""
}

// ownsAddr reports whether the host has the address.
func (n *Node) ownsAddr(addr string) bool {
	if n.Name == addr {
		return true
	}
	for _, a := range n.Loopbacks {
		if a == addr {
			return true
		}
	}
	for _, name := range n.Order {
		if ifc := n.Ifaces[name]; ifc != nil && ifc.Addr == addr {
			return true
		}
	}
	return false
}

// ifaceToward returns the address of n's interface whose peer is peerID.
func (s *Sim) ifaceToward(n *Node, peerID string) string {
	for _, name := range n.Order {
		ifc := n.Ifaces[name]
		if ifc != nil && ifc.PeerNode == peerID {
			return ifc.Addr
		}
	}
	return ""
}

// returnPath returns the one-way delay from n back toward the prober's
// source.  Return routing is independent of forward routing and may be
// asymmetric; a simple shortest-path over the node graph is good enough and
// keeps the model honest.
func (s *Sim) returnPath(n *Node, src *Node) float64 {
	return s.returnDelay(n, src, map[string]bool{n.ID: true})
}

func (s *Sim) returnDelay(n, src *Node, seen map[string]bool) float64 {
	if n == src {
		return 0
	}
	best := -1.0
	for _, name := range n.Order {
		ifc := n.Ifaces[name]
		if ifc == nil {
			continue
		}
		next := s.Nodes[ifc.PeerNode]
		if next == nil || seen[next.ID] {
			continue
		}
		seen[next.ID] = true
		sub := s.returnDelay(next, src, seen)
		seen[next.ID] = false
		if sub < 0 {
			continue
		}
		d := ifc.DelayMs + sub
		if best < 0 || d < best {
			best = d
		}
	}
	return best
}

func (n *Node) outerTTLValue(returnMs float64, base int) int {
	switch n.OuterTTL {
	case OuterTTLFixed255:
		return 255
	case OuterTTLRandom:
		return 1 + n.rng.Intn(254)
	case OuterTTLZero:
		return 0
	default:
		hops := int(returnMs/5.0) + 1
		v := base - hops
		if v < 1 {
			v = 1
		}
		return v
	}
}

// AddrOfIface returns the address of a named interface (test helper).
func (n *Node) AddrOfIface(name string) string {
	if ifc := n.Ifaces[name]; ifc != nil {
		return ifc.Addr
	}
	return ""
}

// AllAddrs lists every address owned by the node.
func (n *Node) AllAddrs() []string {
	out := append([]string{}, n.Loopbacks...)
	for _, name := range n.Order {
		if ifc := n.Ifaces[name]; ifc != nil {
			out = append(out, ifc.Addr)
		}
	}
	if n.Kind == KindHost {
		out = append([]string{n.Name}, out...)
	}
	return out
}

// LookupNode is a convenience for the evaluator.
func (s *Sim) LookupNode(addr string) *Node { return s.byAddr[strings.TrimSpace(addr)] }

// InterfacesOnForwards returns the set of interface addresses that carry a
// probe on some source->destination path (ingress and egress both).
func (s *Sim) InterfacesOnForwards(src, dst string, probes int) map[string]bool {
	out := map[string]bool{}
	for _, sp := range portSpray(probes) {
		for ttl := 1; ttl <= 48; ttl++ {
			rep, recs := s.Send(Probe{SrcIP: src, DstIP: dst, SrcPort: sp, DstPort: 33434, Proto: 17, TTL: ttl})
			for _, r := range recs {
				n := s.Nodes[r.NodeID]
				if n == nil {
					continue
				}
				out[n.ID] = true
				if ifc := n.Ifaces[r.Iface]; ifc != nil {
					out[ifc.Addr] = true
				}
				if peer := s.Nodes[r.PeerID]; peer != nil {
					for _, pn := range peer.Order {
						if pic := peer.Ifaces[pn]; pic != nil && pic.PeerNode == n.ID {
							out[pic.Addr] = true
						}
					}
				}
			}
			if rep.Kind == ReplyEcho {
				break
			}
		}
	}
	return out
}

func portSpray(n int) []uint16 {
	if n <= 0 {
		return nil
	}
	out := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, uint16(30001+i*97))
	}
	return out
}

// ObservableReplyAddrs is the oracle upper bound for interface discovery: the
// set of source addresses that reply to an exhaustive TTL and header sweep,
// including destination variation (which is what destination-keyed balancing
// answers to).  No prober can see an address outside this set; recall against
// it measures how much of the observable network the prober actually found.
func (s *Sim) ObservableReplyAddrs(src, dst string) map[string]bool {
	out := map[string]bool{}
	base := Probe{SrcIP: src, DstIP: dst, Proto: 17, DstPort: 33434}
	for i := 0; i < 120; i++ {
		q := base
		q.SrcPort = uint16(20000 + i*331)
		q.DstPort = uint16(33434 + i*17)
		q.TOS = uint8((i % 8) * 16)
		q.IPID = uint16(i*7919 + 1)
		q.FlowLabel = uint32(i*104729 + 1)
		if i%3 == 0 {
			// Stay inside the routing domain while changing the prefix the
			// destination hash sees.
			q.DstIP = fmt.Sprintf("198.%d.%d.%d", 18+i%200, 1+(i*7)%250, 9)
		}
		for ttl := 1; ttl <= 32; ttl++ {
			q.TTL = ttl
			rep, _ := s.Send(q)
			if rep.Kind == ReplyEcho {
				break
			}
			if rep.Kind != ReplyNone && rep.SrcAddr != "" {
				out[rep.SrcAddr] = true
			}
		}
	}
	return out
}
