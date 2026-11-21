package probe

import (
	"fmt"
	"math"
	"math/rand"
	"sort"

	"topomap/internal/sim"
)

// Options controls prober effort and statistical stopping.
type Options struct {
	// Confidence is the target probability that a hop's next-hop set is
	// complete (0 < Confidence < 1).
	Confidence float64
	// Margin is the tolerated upper bound on the probability mass of a
	// branch that was never observed.
	Margin float64
	// MaxProbesPerFlow caps probes spent on one flow.
	MaxProbesPerFlow int
	// MaxFlows caps the number of distinct flows explored.
	MaxFlows int
	// MinSamplesPerHop is the floor below which a hop is never declared
	// complete.
	MinSamplesPerHop int
	// FieldSweepSamples is the number of paired perturbations tried per
	// header field at each hop.
	FieldSweepSamples int
	// MaxProbes is the global budget.
	MaxProbes int
	// Quiet disables progress logging.
	Quiet bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Confidence:        0.95,
		Margin:            0.15,
		MaxProbesPerFlow:  64,
		MaxFlows:          24,
		MinSamplesPerHop:  8,
		FieldSweepSamples: 10,
		MaxProbes:         5000,
	}
}

type prober struct {
	net  *sim.Sim
	opts Options
	src  string
	dst  string
	rng  *rand.Rand

	probes   int
	res      *Result
	records  []Record
	attempts []Attempt
	warnings []string

	depth int // last TTL that answered the reference flow

	// Alias state (filled by cluster, refined after every pass).
	clusters  []*cluster
	addrToDev map[string]string
	devIPID   map[string]string
	devToNode map[string]string

	// Discovery products.
	fields   []FieldInfluence
	evidence []Evidence
	lb       []LBFinding
	steering []sim.HashField

	// Per-hop field statistics.
	hopFields map[int]map[sim.HashField]*fstat
	spray     map[int]float64
	lbMode    map[int]string

	// Scan products.
	flows    []sim.Probe
	paths    []*Path
	hopDevs  map[int]map[string]int
	hopPkts  map[int]int
	hopNone  map[int]int
	hopAddrs map[int]map[string]int

	rounds int

	mergedGroups []Path
	ifaceNodes   []IfaceNode
}

// Run executes the discovery pipeline against the simulator.
func Run(net *sim.Sim, src, dest string, opts Options) *Result {
	return RunNamed(net, "", src, dest, opts)
}

// RunNamed is Run with the scenario name recorded for reporting.
func RunNamed(net *sim.Sim, scenario, src, dest string, opts Options) *Result {
	opts = normalize(opts)
	p := &prober{
		net: net, opts: opts, src: src, dst: dest,
		rng:       rand.New(rand.NewSource(0x5eed)),
		addrToDev: map[string]string{},
		devIPID:   map[string]string{},
		devToNode: map[string]string{},
		hopFields: map[int]map[sim.HashField]*fstat{},
		spray:     map[int]float64{},
		lbMode:    map[int]string{},
		hopDevs:   map[int]map[string]int{},
		hopPkts:   map[int]int{},
		hopNone:   map[int]int{},
		hopAddrs:  map[int]map[string]int{},
	}
	p.res = &Result{Scenario: scenario, Src: src, Dest: dest, Confidence: opts.Confidence}

	p.recon()            // pass A: reference walk + port spray
	p.cluster(p.records) // initial alias resolution
	p.detectLB()         // pass B: per-hop policy + steering fields
	p.cluster(p.records) // refine aliases with the new addresses
	// hopDevs is rebuilt from the final clusters in nodes(); until then keep
	// it fresh so analyze sees consistent device counts.
	p.rebuildHopDevs()
	p.chooseFlows() // pass C: main scan
	p.scan()
	p.cluster(p.records) // final alias resolution
	p.analyze()
	p.buildGraph()

	p.res.Fields = p.fields
	p.res.Evidence = p.evidence
	p.res.Records = p.records
	p.res.Attempts = p.attempts
	p.res.Warnings = p.warnings
	return p.res
}

// rebuildHopDevs recomputes the per-hop device histogram from the raw
// address histogram and the current alias clusters.
func (p *prober) rebuildHopDevs() {
	p.hopDevs = map[int]map[string]int{}
	for ttl, m := range p.hopAddrs {
		p.hopDevs[ttl] = map[string]int{}
		for a, c := range m {
			p.hopDevs[ttl][p.deviceOf(a)] += c
		}
	}
}

func (p *prober) trace(fmtStr string, args ...any) {
	if p.opts.Quiet {
		return
	}
	fmt.Printf("[probe] "+fmtStr+"\n", args...)
}

func normalize(o Options) Options {
	if o.Confidence <= 0 || o.Confidence >= 1 {
		o.Confidence = 0.95
	}
	if o.Margin <= 0 || o.Margin >= 1 {
		o.Margin = 0.15
	}
	if o.MaxProbesPerFlow <= 0 {
		o.MaxProbesPerFlow = 64
	}
	if o.MaxFlows <= 0 {
		o.MaxFlows = 24
	}
	if o.MinSamplesPerHop <= 0 {
		o.MinSamplesPerHop = 8
	}
	if o.FieldSweepSamples <= 0 {
		o.FieldSweepSamples = 10
	}
	if o.MaxProbes <= 0 {
		o.MaxProbes = 5000
	}
	return o
}

// ---------------------------------------------------------------------------
// Sending and recording

func (p *prober) send(pkt sim.Probe, group string) sim.Reply {
	p.probes++
	rep, recs := p.net.Send(pkt)
	p.records = append(p.records, Record{
		Round: 1, TTL: pkt.TTL, SrcIP: pkt.SrcIP, DstIP: pkt.DstIP,
		SrcPort: int(pkt.SrcPort), DstPort: int(pkt.DstPort), Proto: int(pkt.Proto),
		TOS: int(pkt.TOS), IPID: int(pkt.IPID), ReplyIPID: int(rep.IPID),
		ReplyAddr: rep.SrcAddr, ReplyKind: kindName(rep.Kind),
		OuterTTL: rep.OuterTTL, RTTMs: rep.RTTMs, FlowGroup: group, Hop: pkt.TTL,
	})
	var truth []string
	for _, r := range recs {
		truth = append(truth, r.NodeID+"/"+r.Iface)
	}
	p.attempts = append(p.attempts, Attempt{
		FlowKey: FlowKey(pkt), TTL: pkt.TTL, Probe: pkt, Reply: rep, Truth: truth,
	})
	return rep
}

func (p *prober) baseProbe(flow int) sim.Probe {
	return sim.Probe{
		SrcIP: p.src, DstIP: p.dst,
		SrcPort: uint16(20000 + 7*flow), DstPort: 33434,
		Proto: 17, TOS: 0, IPID: 0, FlowLabel: 0, TTL: 1,
	}
}

// vary sets one field to a deterministic value derived from v.
func (p *prober) vary(base sim.Probe, f sim.HashField, v int) sim.Probe {
	q := base
	switch f {
	case sim.FieldSrcIP:
		q.SrcIP = ipv4(p.src, (v%200)+1)
	case sim.FieldDstIP:
		// Vary the prefix as well as the host part: per-destination
		// balancing hashes the prefix, so a host-only change is invisible.
		o := splitOctets(p.dst)
		if len(o) == 4 {
			q.DstIP = fmt.Sprintf("%d.%d.%d.%d", 198, 100+(v%40), 7+(v/40)%90, o[3])
		}
	case sim.FieldSrcPort:
		q.SrcPort = uint16(40000 + (v*97)%20000)
	case sim.FieldDstPort:
		q.DstPort = uint16(33434 + (v*131)%20000)
	case sim.FieldProto:
		if v%2 == 0 {
			q.Proto = 17
		} else {
			q.Proto = 6
		}
	case sim.FieldTOS:
		q.TOS = uint8((v % 8) * 16)
	case sim.FieldIPID:
		q.IPID = uint16(v*7919 + 1)
	case sim.FieldFlowLabel:
		q.FlowLabel = uint32(v*104729 + 1)
	}
	return q
}

func ipv4(base string, last int) string {
	o := splitOctets(base)
	if len(o) != 4 {
		return base
	}
	return fmt.Sprintf("%d.%d.%d.%d", o[0], o[1], o[2], last)
}

func splitOctets(s string) []int {
	var out []int
	cur, n := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			cur = cur*10 + int(c-'0')
			n++
		} else if c == '.' {
			out = append(out, cur)
			cur, n = 0, 0
		} else {
			return nil
		}
	}
	if n > 0 {
		out = append(out, cur)
	}
	return out
}

func kindName(k sim.ReplyKind) string {
	switch k {
	case sim.ReplyEcho:
		return "echo"
	case sim.ReplyTimeExceeded:
		return "time-exceeded"
	default:
		return "none"
	}
}

func (p *prober) deviceOf(addr string) string {
	if addr == "" {
		return ""
	}
	if d, ok := p.addrToDev[addr]; ok {
		return d
	}
	return "addr:" + addr
}

func (p *prober) budgetLeft() bool { return p.probes < p.opts.MaxProbes }

var _ = sort.Strings
var _ = math.Erf
