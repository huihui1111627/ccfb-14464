package sim

import "testing"

func TestSendReachesDest(t *testing.T) {
	for _, name := range ScenarioList() {
		sc, err := LoadScenario(name, 7)
		if err != nil {
			t.Fatal(err)
		}
		rep, recs := sc.Sim.Send(Probe{SrcIP: sc.Src, DstIP: sc.Dest, SrcPort: 40000, DstPort: 33434, Proto: 17, TTL: 64})
		if rep.Kind != ReplyEcho {
			t.Fatalf("%s: expected echo reply, got %+v", name, rep)
		}
		if len(recs) == 0 {
			t.Fatalf("%s: no trace", name)
		}
		if recs[len(recs)-1].PeerID != "D" && name != "stress" {
			t.Logf("%s: last hop peer=%s", name, recs[len(recs)-1].PeerID)
		}
	}
}

func TestTTLExpiryAnswers(t *testing.T) {
	sc, _ := LoadScenario("diamond", 7)
	rep, _ := sc.Sim.Send(Probe{SrcIP: sc.Src, DstIP: sc.Dest, SrcPort: 1, DstPort: 2, Proto: 17, TTL: 1})
	if rep.Kind != ReplyTimeExceeded {
		t.Fatalf("ttl=1 expected time exceeded, got %+v", rep)
	}
	if rep.SrcAddr != "10.0.1.1" {
		t.Fatalf("expected R0 ingress address, got %s", rep.SrcAddr)
	}
}

func TestFlowLBVariesPath(t *testing.T) {
	sc, _ := LoadScenario("diamond", 7)
	seen := map[string]bool{}
	for p := 0; p < 40; p++ {
		rep, recs := sc.Sim.Send(Probe{SrcIP: sc.Src, DstIP: sc.Dest, SrcPort: uint16(20000 + p), DstPort: 33434, Proto: 17, TTL: 3})
		key := ""
		for _, r := range recs {
			key += r.Iface
		}
		seen[key] = true
		if rep.Kind == ReplyNone {
			continue
		}
	}
	if len(seen) < 2 {
		t.Fatalf("expected multiple paths at ttl=3, saw %v", seen)
	}
}
