// bench runs every scenario, scores it against ground truth and writes one
// report per scenario plus a combined summary.  This is the acceptance run.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"topomap/internal/eval"
	"topomap/internal/probe"
	"topomap/internal/sim"
)

type row struct {
	Scenario     string              `json:"scenario"`
	Probes       int                 `json:"probes"`
	Flows        int                 `json:"flows"`
	Seconds      float64             `json:"seconds"`
	Interface    eval.InterfaceScore `json:"interface"`
	Device       eval.DeviceScore    `json:"device"`
	FalseLinks   int                 `json:"false_links"`
	GapEdges     int                 `json:"gap_edges"`
	Classic      eval.ClassicScore   `json:"classic"`
	Unobservable []string            `json:"unobservable_devices,omitempty"`
}

func main() {
	out := flag.String("out", "out", "output directory")
	seed := flag.Int64("seed", 7, "simulator seed")
	conf := flag.Float64("confidence", 0.95, "confidence target")
	margin := flag.Float64("margin", 0.15, "missing-branch mass margin")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var rows []row
	for _, name := range sim.ScenarioList() {
		sc, err := sim.LoadScenario(name, *seed)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		opts := probe.DefaultOptions()
		opts.Confidence = *conf
		opts.Margin = *margin
		opts.Quiet = true
		start := time.Now()
		res := probe.RunNamed(sc.Sim, name, sc.Src, sc.Dest, opts)
		tr := eval.Compare(sc, res)
		elapsed := time.Since(start).Seconds()

		if err := eval.WriteHTML(filepath.Join(*out, name+".html"), sc, res, tr); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		full := map[string]any{"result": res, "truth": tr}
		if b, err := json.MarshalIndent(full, "", "  "); err == nil {
			_ = os.WriteFile(filepath.Join(*out, name+".json"), b, 0o644)
		}
		exp := res.Export()
		exp.Margin = opts.Margin
		if b, err := json.MarshalIndent(exp, "", "  "); err == nil {
			_ = os.WriteFile(filepath.Join(*out, name+"-summary.json"), b, 0o644)
		}

		rows = append(rows, row{
			Scenario: name, Probes: tr.Probes, Flows: tr.Flows, Seconds: elapsed,
			Interface: tr.Interface, Device: tr.Device,
			FalseLinks: tr.FalseLinks, GapEdges: tr.GapEdges, Classic: tr.Classic,
			Unobservable: tr.UnobservableDevs,
		})
		fmt.Printf("%-10s probes=%-5d flows=%-3d iface P/R %5.1f%%/%5.1f%%  device P/R %5.1f%%/%5.1f%%  false=%d gap=%d  classic false=%d recall=%.1f%%  (%.2fs)\n",
			name, tr.Probes, tr.Flows,
			100*tr.Interface.Precision, 100*tr.Interface.Recall,
			100*tr.Device.Precision, 100*tr.Device.Recall,
			tr.FalseLinks, tr.GapEdges, tr.Classic.FalseLinks, 100*tr.Classic.Recall, elapsed)
	}
	if b, err := json.MarshalIndent(rows, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(*out, "summary.json"), b, 0o644)
	}
	index := "<!DOCTYPE html><meta charset=utf-8><title>topomap reports</title>" +
		"<style>body{font:14px system-ui;background:#0b0e14;color:#e6edf7;padding:24px}a{color:#4fa3ff}li{margin:6px 0}</style>" +
		"<h1>topomap — 多路径拓扑测绘</h1><ul>"
	for _, r := range rows {
		index += fmt.Sprintf("<li><a href=%q>%s</a> — 出接口级 P/R %.1f%%/%.1f%%，设备级 P/R %.1f%%/%.1f%%，假链路 %d，探测 %d</li>",
			r.Scenario+".html", r.Scenario,
			100*r.Interface.Precision, 100*r.Interface.Recall,
			100*r.Device.Precision, 100*r.Device.Recall, r.FalseLinks, r.Probes)
	}
	index += "</ul>"
	_ = os.WriteFile(filepath.Join(*out, "index.html"), []byte(index), 0o644)
	fmt.Printf("\nreports in %s\n", *out)
}
