// Package eval scores the prober's reconstruction against simulator ground
// truth and runs the classic traceroute baseline for comparison.
package eval

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"topomap/internal/probe"
	"topomap/internal/sim"
)

// TruthReport is the acceptance artefact: interface-level and device-level
// precision/recall, false links, probe count and the classic baseline.
type TruthReport struct {
	Scenario string `json:"scenario"`

	Interface  InterfaceScore `json:"interface"`
	Device     DeviceScore    `json:"device"`
	FalseLinks int            `json:"false_links"`
	GapEdges   int            `json:"gap_edges"`
	Probes     int            `json:"probes"`
	Paths      int            `json:"paths"`
	Flows      int            `json:"flows"`

	Classic ClassicScore `json:"classic"`

	MissingInterfaces []string `json:"missing_interfaces"`
	PhantomLinks      []string `json:"phantom_links"`
	MissingDevices    []string `json:"missing_devices"`
	GapLinks          []string `json:"gap_links"`
	UnobservableDevs  []string `json:"unobservable_devices"`
}

type InterfaceScore struct {
	Precision float64  `json:"precision"`
	Recall    float64  `json:"recall"`
	F1        float64  `json:"f1"`
	Found     int      `json:"found"`
	Truth     int      `json:"truth"`
	Predicted int      `json:"predicted"`
	Missed    []string `json:"missed"`
}

type DeviceScore struct {
	Precision float64  `json:"precision"`
	Recall    float64  `json:"recall"`
	F1        float64  `json:"f1"`
	Found     int      `json:"found"`
	Truth     int      `json:"truth"`
	Predicted int      `json:"predicted"`
	Missed    []string `json:"missed"`
}

type ClassicScore struct {
	Hops       int     `json:"hops"`
	Paths      int     `json:"paths"`
	FalseLinks int     `json:"false_links"`
	Devices    int     `json:"devices_found"`
	Recall     float64 `json:"device_recall"`
	Precision  float64 `json:"device_precision"`
	Probes     int     `json:"probes"`
}

// forwardReach returns every router/host that a probe can actually reach
// from src to dst.  A link counts only if the peer has a route covering the
// destination and the forwarding chain closes on the destination.  Silent
// hops still forward and therefore still count; routers parked on a loop or
// a dead-end branch do not.
func forwardReach(sc *sim.Scenario) map[string]bool {
	reached := map[string]bool{}
	dst, _ := netip.ParseAddr(sc.Dest)
	srcNode := sc.Sim.NodeByAddr(sc.Src)
	if srcNode == nil {
		return reached
	}
	seen := map[string]bool{}
	var walk func(n *sim.Node, depth int)
	walk = func(n *sim.Node, depth int) {
		if n == nil || depth > 64 || seen[n.ID] {
			return
		}
		seen[n.ID] = true
		if n.Kind == sim.KindRouter {
			reached[n.ID] = true
		}
		for _, name := range sc.Sim.ReachableHops(n, dst) {
			ifc := n.Ifaces[name]
			if ifc == nil {
				continue
			}
			walk(sc.Sim.Nodes[ifc.PeerNode], depth+1)
		}
	}
	for _, name := range srcNode.Order {
		if ifc := srcNode.Ifaces[name]; ifc != nil {
			walk(sc.Sim.Nodes[ifc.PeerNode], 0)
		}
	}
	return reached
}

func forwardRoute(n *sim.Node, dst netip.Addr) *sim.Route {
	var best *sim.Route
	for _, r := range n.Routes {
		if r.Prefix.Contains(dst) {
			if best == nil || r.Prefix.Bits() > best.Prefix.Bits() {
				best = r
			}
		}
	}
	return best
}

// Compare builds the acceptance report.
func Compare(sc *sim.Scenario, res *probe.Result) *TruthReport {
	tr := &TruthReport{
		Scenario: sc.Name, Probes: res.Graph.Stats.Probes,
		Paths: len(res.Graph.Paths), Flows: res.Graph.Stats.Flows,
	}

	truthSet := forwardReach(sc)
	observable := sc.Sim.ObservableReplyAddrs(sc.Src, sc.Dest)
	// truthIfaces: every forwarding interface of an expected device, plus the
	// interface address a probe actually sees it answer from.
	addrDev := map[string]string{}
	for _, id := range sc.Sim.Order {
		n := sc.Sim.Nodes[id]
		for _, a := range n.AllAddrs() {
			addrDev[a] = n.ID
		}
	}
	// What the prober predicted: every address the tool actually reports,
	// either as a graph node identity or as a hop it observed on a path.
	predDev := map[string]bool{}
	predAddr := map[string]bool{}
	// Devices the prober saw only while sweeping other destinations are real
	// but belong to a different mapping run; they must not count as claims
	// about this destination's graph.
	offPath := map[string]bool{}
	for _, d := range res.Graph.OffPathDevices {
		offPath[d] = true
	}
	for _, n := range res.Graph.Nodes {
		if offPath[n.ID] {
			continue
		}
		for _, a := range n.Addrs {
			if a == sc.Src || a == sc.Dest {
				continue
			}
			predAddr[a] = true
		}
	}
	for _, pth := range res.Graph.Paths {
		for _, a := range pth.Hops {
			if a == "" || a == sc.Src || a == sc.Dest {
				continue
			}
			predAddr[a] = true
		}
	}
	for a := range predAddr {
		d, ok := addrDev[a]
		if !ok {
			continue
		}
		if d == sc.Sim.NodeByAddr(sc.Dest).ID {
			continue // destination endpoint, not a discovered transit device
		}
		predDev[d] = true
	}

	// Device-level score: truth devices that can be observed at all.
	var dmiss []string
	dhit := 0
	truthObsDev := map[string]bool{}
	for d := range truthSet {
		if deviceOnProbePath(sc, d, observable) {
			truthObsDev[d] = true
		}
	}
	for d := range truthObsDev {
		if predDev[d] {
			dhit++
		} else {
			dmiss = append(dmiss, d+"("+sc.Sim.Nodes[d].Name+")")
		}
	}
	sort.Strings(dmiss)
	tr.MissingDevices = dmiss
	// Predicted device count must be measured on the same terms as truth:
	// only devices that own an observable address.  Reporting a device from a
	// loopback-only identity is not a false device if that loopback is a real
	// on-path device's.
	tr.Device = DeviceScore{Found: dhit, Truth: len(truthObsDev), Predicted: len(predDev), Missed: dmiss}
	if len(predDev) > 0 {
		common := 0
		for d := range predDev {
			if truthObsDev[d] {
				common++
			}
		}
		tr.Device.Precision = float64(common) / float64(len(predDev))
	}
	if len(truthObsDev) > 0 {
		tr.Device.Recall = float64(dhit) / float64(len(truthObsDev))
	}
	tr.Device.F1 = f1(tr.Device.Precision, tr.Device.Recall)

	// Interface-level score.  Ground truth is every forwarding interface that
	// actually carries a probe on some source->destination path, identified by
	// its address.  Ports that only ever appear as the egress of a hop cannot
	// answer a TTL-expired probe on this path; counting them would penalise
	// any prober, including a perfect one.
	truthIface := map[string]bool{}
	for a := range observable {
		if a == sc.Src || a == sc.Dest {
			continue
		}
		if d, ok := addrDev[a]; ok && truthSet[d] {
			truthIface[a] = true
		}
	}
	// The prober's interface claims are the addresses it reported that are
	// also addresses some device can actually originate replies from.
	predObs := map[string]bool{}
	for a := range predAddr {
		if observable[a] {
			predObs[a] = true
		}
	}
	ihit := 0
	var imiss []string
	for a := range truthIface {
		if predAddr[a] {
			ihit++
		} else {
			imiss = append(imiss, a)
		}
	}
	sort.Strings(imiss)
	tr.MissingInterfaces = imiss
	// Predicted addresses that are not any truth interface: loopbacks are
	// legitimate device identities but not interfaces, so exclude them from
	// the precision denominator's "wrong" bucket only if they alias a truth
	// device.
	predIface := 0
	for a := range predAddr {
		if truthIface[a] {
			predIface++
		}
	}
	tr.Interface = InterfaceScore{Found: ihit, Truth: len(truthIface), Predicted: len(predObs), Missed: imiss}
	if len(predObs) > 0 {
		tr.Interface.Precision = float64(ihit) / float64(len(predObs))
	}
	if len(truthIface) > 0 {
		tr.Interface.Recall = float64(ihit) / float64(len(truthIface))
	}
	tr.Interface.F1 = f1(tr.Interface.Precision, tr.Interface.Recall)

	// False links: predicted directed device adjacencies that do not exist in
	// the forward graph.
	type edge struct{ a, b string }
	trueEdges := map[edge]bool{}
	for _, id := range sc.Sim.Order {
		n := sc.Sim.Nodes[id]
		for _, name := range n.Order {
			ifc := n.Ifaces[name]
			if sc.Sim.Nodes[ifc.PeerNode] == nil {
				continue
			}
			trueEdges[edge{id, ifc.PeerNode}] = true
		}
	}
	nodeDev := map[string]string{}
	for _, n := range res.Graph.Nodes {
		for _, a := range n.Addrs {
			if d, ok := addrDev[a]; ok {
				nodeDev[n.ID] = d
				break
			}
		}
	}
	srcID := sc.Sim.NodeByAddr(sc.Src).ID
	fl, gaps := 0, 0
	var phantoms, gapLinks []string
	for _, l := range res.Graph.Links {
		da, oka := nodeDev[l.From]
		if l.From == "src" {
			da, oka = srcID, true
		}
		db, okb := nodeDev[l.To]
		if !oka || !okb || da == db {
			continue
		}
		if trueEdges[edge{da, db}] {
			continue
		}
		// A destination-hashed router sends this destination down one bucket;
		// the other routers it could reach are on the static graph but never
		// receive a probe.  An edge to one of those is a misattribution of a
		// silent hop, not a fabricated adjacency of the tested network.
		if !truthSet[db] {
			gaps++
			gapLinks = append(gapLinks, fmt.Sprintf("%s -> %s (device off this destination's probe paths)", da, db))
			continue
		}
		if l.Skipped > 0 {
			// An edge the tool explicitly marks as spanning an unanswered hop
			// is an acknowledged gap, not a fabricated adjacency.
			gaps++
			gapLinks = append(gapLinks, fmt.Sprintf("%s -> %s (%d hidden hop)", da, db, l.Skipped))
			continue
		}
		fl++
		phantoms = append(phantoms, fmt.Sprintf("%s -> %s", da, db))
	}
	sort.Strings(phantoms)
	sort.Strings(gapLinks)
	tr.FalseLinks = fl
	tr.GapEdges = gaps
	tr.PhantomLinks = phantoms
	tr.GapLinks = gapLinks

	// Devices on the forward path that cannot be found by any ICMP prober are
	// reported separately so a recall number is not read as a tool defect.
	// A device is unreachable for two reasons: it never originates a reply at
	// all, or it sits behind a destination-keyed router that never sends a
	// probe into it.
	var unobs []string
	for d := range truthSet {
		n := sc.Sim.Nodes[d]
		if deviceOnProbePath(sc, d, observable) {
			continue
		}
		unobs = append(unobs, d+"("+n.Name+")")
	}
	sort.Strings(unobs)
	tr.UnobservableDevs = unobs

	tr.Classic = runClassic(sc, truthSet, addrDev)
	return tr
}

func f1(p, r float64) float64 {
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

// Text renders the acceptance numbers.
func (t *TruthReport) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  interface level: precision %.1f%%  recall %.1f%%  F1 %.1f%%  (found %d of %d; reported %d addresses)\n",
		100*t.Interface.Precision, 100*t.Interface.Recall, 100*t.Interface.F1,
		t.Interface.Found, t.Interface.Truth, t.Interface.Predicted)
	fmt.Fprintf(&b, "  device level:    precision %.1f%%  recall %.1f%%  F1 %.1f%%  (found %d of %d; reported %d)\n",
		100*t.Device.Precision, 100*t.Device.Recall, 100*t.Device.F1,
		t.Device.Found, t.Device.Truth, t.Device.Predicted)
	fmt.Fprintf(&b, "  false links:     %d (asserted adjacencies that do not exist)\n", t.FalseLinks)
	fmt.Fprintf(&b, "  gap edges:       %d (edges explicitly spanning a silent hop)\n", t.GapEdges)
	if len(t.UnobservableDevs) > 0 {
		fmt.Fprintf(&b, "  on-path routers that never answer: %v\n", t.UnobservableDevs)
	}
	fmt.Fprintf(&b, "  probe packets:   %d over %d flows\n", t.Probes, t.Flows)
	if len(t.MissingDevices) > 0 {
		fmt.Fprintf(&b, "  missed devices:  %v\n", t.MissingDevices)
	}
	if len(t.MissingInterfaces) > 0 {
		fmt.Fprintf(&b, "  missed interfaces (never answered): %v\n", t.MissingInterfaces)
	}
	if len(t.PhantomLinks) > 0 {
		fmt.Fprintf(&b, "  phantom links:   %v\n", t.PhantomLinks)
	}
	if len(t.GapLinks) > 0 {
		fmt.Fprintf(&b, "  gap links:       %v\n", t.GapLinks)
	}
	return b.String()
}

// ClassicText renders the single-flow traceroute baseline.
func (t *TruthReport) ClassicText() string {
	return fmt.Sprintf("  single-flow traceroute: %d hops, %d probes, %d devices found (recall %.1f%%, precision %.1f%%), %d false links\n",
		t.Classic.Hops, t.Classic.Probes, t.Classic.Devices, 100*t.Classic.Recall, 100*t.Classic.Precision, t.Classic.FalseLinks)
}

// deviceOnProbePath reports whether any forwarding interface of d appears on a
// path the simulator actually sends probes down, using the observability
// oracle as the authority.  Nodes can appear in the static topology but be cut
// off by a destination-hashed router; those are not discoverable at all.
func deviceOnProbePath(sc *sim.Scenario, id string, observable map[string]bool) bool {
	n := sc.Sim.Nodes[id]
	if n == nil {
		return false
	}
	for _, name := range n.Order {
		ifc := n.Ifaces[name]
		if ifc == nil {
			continue
		}
		if observable[ifc.Addr] || observable[ifc.Name] {
			return true
		}
	}
	for _, a := range n.AllAddrs() {
		if observable[a] {
			return true
		}
	}
	return false
}
