package probe

// Export is the stable machine-readable summary of a run.  It is written next
// to the HTML page so dashboards and the acceptance script do not have to
// understand the full internal Result.
type Export struct {
	Scenario   string  `json:"scenario"`
	Src        string  `json:"src"`
	Dest       string  `json:"dest"`
	Confidence float64 `json:"confidence_target"`
	Margin     float64 `json:"margin"`

	Fields   []FieldInfluence `json:"fields"`
	LB       []LBFinding      `json:"lb"`
	Clusters []NodeCluster    `json:"devices"`
	Graph    ExportGraph      `json:"graph"`
	Probes   int              `json:"probes"`
	Flows    int              `json:"flows"`
	Warnings []string         `json:"warnings,omitempty"`
}

// ExportGraph is the reconstructed topology in its published form.
type ExportGraph struct {
	Nodes     []FNode       `json:"nodes"`
	Links     []FLink       `json:"links"`
	Branches  []Branch      `json:"branches"`
	Paths     []Path        `json:"paths"`
	Estimates []HopEstimate `json:"hop_estimates"`
	Anomalies []Anomaly     `json:"anomalies"`
}

// Export builds the stable summary.
func (r *Result) Export() Export {
	g := ExportGraph{}
	if r.Graph != nil {
		g = ExportGraph{
			Nodes: r.Graph.Nodes, Links: r.Graph.Links, Branches: r.Graph.Branches,
			Paths: r.Graph.Paths, Estimates: r.Graph.Estimates, Anomalies: r.Graph.Anomalies,
		}
	}
	return Export{
		Scenario: r.Scenario, Src: r.Src, Dest: r.Dest,
		Confidence: r.Confidence,
		Fields:     r.Fields, LB: r.LBPerHop, Clusters: r.Clusters,
		Graph: g, Probes: r.Graph.Stats.Probes, Flows: r.Graph.Stats.Flows,
		Warnings: r.Warnings,
	}
}
