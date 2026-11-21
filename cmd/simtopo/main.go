// simtopo prints the ground-truth topology of a built-in scenario.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"topomap/internal/sim"
)

func main() {
	name := flag.String("scenario", "diamond", "scenario name")
	seed := flag.Int64("seed", 7, "simulator seed")
	flag.Parse()
	sc, err := sim.LoadScenario(*name, *seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Printf("# scenario %s: %s\n", sc.Name, sc.Desc)
	fmt.Printf("# source %s  destination %s\n", sc.Src, sc.Dest)
	s := sc.Sim
	for _, id := range s.Order {
		n := s.Nodes[id]
		kind := "router"
		if n.Kind == sim.KindHost {
			kind = "host"
		}
		fmt.Printf("node %s %s %s lb=%s silent=%v ttl-dec=%d ipid=%d reply-mode=%d rate=%.0f\n",
			n.ID, kind, n.Name, n.LB, n.Silent, n.TTLDecrement, n.IPIDMode, n.ReplyMode, n.ReplyRate)
		for _, a := range n.Loopbacks {
			fmt.Printf("  loopback %s\n", a)
		}
		for _, name := range n.Order {
			ifc := n.Ifaces[name]
			fmt.Printf("  iface %s addr=%s -> %s/%s delay=%.2fms\n", name, ifc.Addr, ifc.PeerNode, ifc.PeerIface, ifc.DelayMs)
		}
		for _, r := range n.Routes {
			var hs []string
			for _, h := range r.NextHops {
				hs = append(hs, fmt.Sprintf("%s(w%d)", h.Iface, h.Weight))
			}
			fmt.Printf("  route %s -> %v lb=%s\n", r.Prefix, hs, r.LB)
		}
	}
	_ = sort.Strings
}
