// Package probe implements the multi-path topology prober.  It only sees the
// sim.Reply values produced by the network; all discovery -- which header
// fields steer load balancing, how many probes a hop needs, where paths
// merge -- happens here.
package probe

import (
	"sort"
	"sync"

	"topomap/internal/sim"
)

// Attempt is a single probe packet and its outcome, retained as raw evidence.
type Attempt struct {
	FlowKey string    `json:"flow_key"` // identity of the fixed header set
	TTL     int       `json:"ttl"`
	Probe   sim.Probe `json:"probe"`
	Reply   sim.Reply `json:"reply"`
	// Truth is filled by the evaluator run for debugging; empty for the tool.
	Truth []string `json:"truth,omitempty"`
	Round int      `json:"round"`
}

// FlowKey renders the header fields that are held constant within one flow.
// Ports are impossible to keep out of the packet, so they are part of it.
func FlowKey(p sim.Probe) string {
	return p.SrcIP + "|" + p.DstIP + "|" +
		itoa(int(p.SrcPort)) + "|" + itoa(int(p.DstPort)) + "|" +
		itoa(int(p.Proto)) + "|" + itoa(int(p.TOS)) + "|" + itoa(int(p.FlowLabel))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}

// Record is a raw reply row for the web UI.
type Record struct {
	Round     int     `json:"round"`
	TTL       int     `json:"ttl"`
	SrcIP     string  `json:"src_ip"`
	DstIP     string  `json:"dst_ip"`
	SrcPort   int     `json:"src_port"`
	DstPort   int     `json:"dst_port"`
	Proto     int     `json:"proto"`
	TOS       int     `json:"tos"`
	IPID      int     `json:"ip_id"`
	ReplyIPID int     `json:"reply_ipid"`
	ReplyAddr string  `json:"reply_addr"`
	ReplyKind string  `json:"reply_kind"`
	OuterTTL  int     `json:"outer_ttl"`
	RTTMs     float64 `json:"rtt_ms"`
	FlowGroup string  `json:"flow_group"`
	Hop       int     `json:"hop"`
	Note      string  `json:"note,omitempty"`
}

// Path is one observed source-address sequence, hop by hop.  A missing reply
// keeps the empty slot so downstream merging can align by hop index.
type Path struct {
	ID       int       `json:"id"`
	Hops     []string  `json:"hops"` // reply source address per TTL, "" = silent
	RTT      []float64 `json:"rtt_ms"`
	Attempts int       `json:"attempts"`
	FlowKey  string    `json:"flow_key"`
	Weight   int       `json:"weight"`
}

// HopGroup is a TTL position with the devices and representative addresses
// seen there.
type HopGroup struct {
	TTL     int      `json:"ttl"`
	Addrs   []string `json:"addrs"`
	Devices []string `json:"devices"`
}

// IfaceNode is one reply address, attributed to the device that owns it.
// The interface-level graph and the device-level graph are the two views the
// acceptance metrics are reported at.
type IfaceNode struct {
	Addr        string `json:"addr"`
	Device      string `json:"device"`
	DeviceLabel string `json:"device_label"`
	Level       int    `json:"level"`
	Order       int    `json:"order"`
}

// Branch is one arm of a fork, with the numbers the UI annotates it with.
type Branch struct {
	Fork       string  `json:"fork"`
	To         string  `json:"to"`
	Width      int     `json:"width"`
	Samples    int     `json:"samples"`
	Share      float64 `json:"share"`
	MinRTTMs   float64 `json:"min_rtt_ms"`
	MedRTTMs   float64 `json:"med_rtt_ms"`
	ExtraRTTMs float64 `json:"extra_rtt_ms"`
	Skipped    int     `json:"skipped_hops"`
}

// FieldInfluence records what the prober learned about one header field.
type FieldInfluence struct {
	Field      string  `json:"field"`
	Tried      int     `json:"tried"`
	Changes    int     `json:"changes"`
	Influence  float64 `json:"influence"`
	Confidence float64 `json:"confidence"`
	Verdict    string  `json:"verdict"` // "steers", "ignored", "inconclusive"
}

// Evidence is one observation behind a FieldInfluence verdict.
type Evidence struct {
	Field   string `json:"field"`
	Hop     int    `json:"hop"`
	From    string `json:"from"`
	To      string `json:"to"`
	Varying int    `json:"varying"`
}

// NodeCluster is a set of addresses believed to belong to one device.
type NodeCluster struct {
	ID         string   `json:"id"`
	Label      string   `json:"label"`
	Addrs      []string `json:"addrs"`
	Confidence float64  `json:"confidence"`
	Method     []string `json:"methods"`
	IPIDMode   string   `json:"ipid_mode"`
	Level      int      `json:"level"`
	DeviceID   string   `json:"node_id"`
}

// HopEstimate is the statistical estimate of how many next hops a hop has.
type HopEstimate struct {
	TTL        int     `json:"ttl"`
	Observed   int     `json:"observed"`
	Estimate   int     `json:"estimate"`
	Lower      int     `json:"lower"`
	Upper      int     `json:"upper"`
	Confidence float64 `json:"confidence"`
	Probes     int     `json:"probes"`
	Complete   bool    `json:"complete"`
	Reached    bool    `json:"reached"` // true when this TTL position answered at all
}

// Fusion is the reconstructed graph: nodes with addresses, edges between
// consecutive nodes, annotated with width and branch delays.
type Fusion struct {
	Nodes     []FNode       `json:"nodes"`
	Links     []FLink       `json:"links"`
	Branches  []Branch      `json:"branches"`
	Ifaces    []IfaceNode   `json:"ifaces"`
	NGroups   []HopGroup    `json:"hop_groups"`
	Paths     []Path        `json:"paths"`
	Estimates []HopEstimate `json:"hop_estimates"`
	Anomalies []Anomaly     `json:"anomalies"`
	Stats     Stats         `json:"stats"`
}

// FNode is a device in the reconstructed graph.
type FNode struct {
	ID         string   `json:"id"`
	Label      string   `json:"label"`
	Addrs      []string `json:"addrs"`
	Level      int      `json:"level"`
	Kind       string   `json:"kind"` // "src", "router", "unknown", "dst"
	AliasScore float64  `json:"alias_confidence"`
}

// FLink is a directed adjacency between two levels with width = number of
// distinct TTL-aligned transitions observed and latency stats.
type FLink struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	FromLevel int       `json:"from_level"`
	ToLevel   int       `json:"to_level"`
	MinRTTMs  float64   `json:"min_rtt_ms"`
	MedRTTMs  float64   `json:"med_rtt_ms"`
	MaxRTTMs  float64   `json:"max_rtt_ms"`
	BranchRTT []float64 `json:"branch_rtt_ms,omitempty"` // per-branch differential delay
	Width     int       `json:"width"`
	Samples   int       `json:"samples"`
	Flows     int       `json:"flows"`
	Skipped   int       `json:"skipped_hops,omitempty"`
	AliasOnly bool      `json:"alias_only,omitempty"`
}

// Anomaly records a place where a naive traceroute would draw a false link.
type Anomaly struct {
	Kind       string   `json:"kind"`
	TTL        int      `json:"ttl"`
	Addrs      []string `json:"addrs"`
	Devices    []string `json:"devices,omitempty"`
	Detail     string   `json:"detail"`
	Confidence float64  `json:"confidence"`
}

// Stats summarises probe cost and discovery behaviour.
type Stats struct {
	Probes        int `json:"probes"`
	Rounds        int `json:"rounds"`
	Flows         int `json:"flows"`
	SilentHops    int `json:"silent_hops"`
	TTLHidingHops int `json:"ttl_hiding_hops"`
	RateLimited   int `json:"rate_limited"`
	Asymmetric    int `json:"asymmetric"`
}

// Result is everything the prober produced.
type Result struct {
	Scenario   string           `json:"scenario"`
	Src        string           `json:"src"`
	Dest       string           `json:"dest"`
	Confidence float64          `json:"confidence"`
	LBPerHop   []LBFinding      `json:"lb"`
	Fields     []FieldInfluence `json:"fields"`
	Evidence   []Evidence       `json:"field_evidence"`
	Clusters   []NodeCluster    `json:"clusters"`
	Graph      *Fusion          `json:"graph"`
	Records    []Record         `json:"records"`
	Attempts   []Attempt        `json:"attempts"`
	Warnings   []string         `json:"warnings"`
}

// LBFinding describes the load-balancing policy inferred at one hop.
type LBFinding struct {
	TTL        int      `json:"ttl"`
	Mode       string   `json:"mode"`
	Evidence   string   `json:"evidence"`
	Fields     []string `json:"fields"`
	Branches   int      `json:"branches"`
	Confidence float64  `json:"confidence"`
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var _ = sync.Mutex{}
