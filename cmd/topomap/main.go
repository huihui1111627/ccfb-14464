// topomap probes a simulated network and reports the discovered topology.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"topomap/internal/eval"
	"topomap/internal/probe"
	"topomap/internal/sim"
)

func main() {
	scenario := flag.String("scenario", "diamond", "simulated network: diamond|multitier|quirks|stress")
	seed := flag.Int64("seed", 7, "simulator seed")
	conf := flag.Float64("confidence", 0.95, "confidence target for hop completeness (0-1)")
	margin := flag.Float64("margin", 0.15, "tolerated missing branch mass before a hop is declared complete")
	maxFlows := flag.Int("flows", 24, "maximum number of distinct flows to probe")
	perFlow := flag.Int("per-flow", 64, "maximum probes per flow")
	sweep := flag.Int("sweep", 24, "field-sweep samples per header field")
	jsonOut := flag.String("json", "", "write full result JSON here")
	summaryOut := flag.String("summary", "", "write the stable summary JSON here")
	htmlOut := flag.String("html", "", "write interactive HTML report here")
	quiet := flag.Bool("quiet", false, "suppress progress output")
	flag.Parse()

	sc, err := sim.LoadScenario(*scenario, *seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	opts := probe.DefaultOptions()
	opts.Confidence = *conf
	opts.Margin = *margin
	opts.MaxFlows = *maxFlows
	opts.MaxProbesPerFlow = *perFlow
	opts.FieldSweepSamples = *sweep
	opts.Quiet = *quiet

	res := probe.RunNamed(sc.Sim, sc.Name, sc.Src, sc.Dest, opts)

	tr := eval.Compare(sc, res)
	if !*quiet {
		printSummary(sc, res, tr)
	}
	if *jsonOut != "" {
		if err := writeJSON(*jsonOut, res, tr); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if *summaryOut != "" {
		ex := res.Export()
		ex.Margin = opts.Margin
		b, err := json.MarshalIndent(ex, "", "  ")
		if err == nil {
			err = os.WriteFile(*summaryOut, b, 0o644)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if *htmlOut != "" {
		if err := eval.WriteHTML(*htmlOut, sc, res, tr); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	_ = sort.Strings
}

func writeJSON(path string, res *probe.Result, tr *eval.TruthReport) error {
	payload := map[string]any{"result": res, "truth": tr}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func printSummary(sc *sim.Scenario, res *probe.Result, tr *eval.TruthReport) {
	fmt.Printf("scenario: %s\n  %s\n", sc.Name, sc.Desc)
	fmt.Printf("source %s -> destination %s\n\n", sc.Src, sc.Dest)

	fmt.Println("== header fields that steer load balancing ==")
	for _, f := range res.Fields {
		fmt.Printf("  %-10s influence %5.2f  confidence %5.2f  %s\n", f.Field, f.Influence, f.Confidence, f.Verdict)
	}

	fmt.Println("\n== hop estimates ==")
	fmt.Printf("  %-4s %-8s %-9s %-10s %s\n", "ttl", "observed", "estimate", "probes", "complete")
	for _, e := range res.Graph.Estimates {
		fmt.Printf("  %-4d %-8d %-9d %-10d %v\n", e.TTL, e.Observed, e.Estimate, e.Probes, e.Complete)
	}

	fmt.Println("\n== device clusters ==")
	for _, c := range res.Clusters {
		fmt.Printf("  %s %v  confidence %.2f  %v  ip-id=%s\n", c.ID, c.Addrs, c.Confidence, c.Method, c.IPIDMode)
	}

	fmt.Println("\n== anomalies ==")
	for _, a := range res.Graph.Anomalies {
		fmt.Printf("  [%s] hop %d: %s\n", a.Kind, a.TTL, a.Detail)
	}

	fmt.Println("\n== probes ==")
	fmt.Printf("  sent %d probes in %d flows\n", res.Graph.Stats.Probes, len(res.Graph.Paths))

	fmt.Println("\n== accuracy vs ground truth ==")
	fmt.Print(tr.Text())
	fmt.Println("\nclassic traceroute comparison")
	fmt.Print(tr.ClassicText())
}
