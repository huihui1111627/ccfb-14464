package eval

import (
	"os"
	"path/filepath"
	"testing"

	"topomap/internal/probe"
	"topomap/internal/sim"
)

func TestAcceptanceScenarios(t *testing.T) {
	for _, name := range sim.ScenarioList() {
		sc, err := sim.LoadScenario(name, 7)
		if err != nil {
			t.Fatal(err)
		}
		opts := probe.DefaultOptions()
		opts.Quiet = true
		res := probe.RunNamed(sc.Sim, name, sc.Src, sc.Dest, opts)
		tr := Compare(sc, res)
		if tr.FalseLinks != 0 {
			t.Errorf("%s: %d false links: %v", name, tr.FalseLinks, tr.PhantomLinks)
		}
		if tr.Interface.Recall < 0.99 {
			t.Errorf("%s: interface recall %.2f", name, tr.Interface.Recall)
		}
		if tr.Interface.Precision < 0.99 {
			t.Errorf("%s: interface precision %.2f", name, tr.Interface.Precision)
		}
		if tr.Device.Recall < 0.99 {
			t.Errorf("%s: device recall %.2f (missed %v)", name, tr.Device.Recall, tr.MissingDevices)
		}
		if tr.Device.Precision < 0.99 {
			t.Errorf("%s: device precision %.2f", name, tr.Device.Precision)
		}
		// The tool must beat a single-flow traceroute on device recall in
		// every scenario that actually forks.
		if tr.Paths > 1 && tr.Classic.Recall >= tr.Device.Recall {
			t.Errorf("%s: classic recall %.2f not beaten by %.2f", name, tr.Classic.Recall, tr.Device.Recall)
		}
	}
}

func TestHTMLReportWrites(t *testing.T) {
	sc, _ := sim.LoadScenario("diamond", 7)
	opts := probe.DefaultOptions()
	opts.Quiet = true
	res := probe.RunNamed(sc.Sim, "diamond", sc.Src, sc.Dest, opts)
	tr := Compare(sc, res)
	dir := t.TempDir()
	p := filepath.Join(dir, "r.html")
	if err := WriteHTML(p, sc, res, tr); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 10000 {
		t.Fatalf("report too small: %d bytes", len(b))
	}
}
