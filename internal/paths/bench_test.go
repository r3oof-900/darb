package paths

import (
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
)

// shape of a synthetic access graph: workloads -> service accounts -> roles
// (some chained) -> jewels, each read being CAN_READ + CAN_DECRYPT under a
// derived CAN_READ_PLAINTEXT, as the access builder produces.
type shape struct {
	workloads, accounts, roles, jewels, readsPerRole, chains int
}

func synthetic(s shape, seed uint64) (g *graph.Graph, entries, jewels []graph.NodeID) {
	r := rand.New(rand.NewPCG(seed, 1)) //nolint:gosec // G404: deterministic test data, not security.
	b := graph.NewBuilder()
	node := func(kind, name string, i int) graph.NodeID {
		id := fmt.Sprintf("%s/%s/%d", kind, name, i)
		return b.Node(model.ID(id), model.NodeKind(kind), id)
	}
	edge := func(from, to graph.NodeID, kind graph.Kind, sub string) graph.EdgeID {
		return b.Edge(&graph.Edge{From: from, To: to, Kind: kind, Sub: sub, For: graph.NoNode, Verdict: eval.Allow, Confidence: graph.High})
	}
	var ws, sas, roles, js, keys []graph.NodeID
	for i := range s.workloads {
		ws = append(ws, node("w", "workload", i))
	}
	for i := range s.accounts {
		sas = append(sas, node("sa", "account", i))
	}
	for i := range s.roles {
		roles = append(roles, node("role", "role", i))
	}
	for i := range s.jewels {
		js = append(js, node("jewel", "bucket", i))
		keys = append(keys, node("key", "key", i))
	}
	for i, w := range ws {
		sa := sas[i%len(sas)]
		edge(w, sa, graph.RunsAs, "")
		edge(w, sa, graph.RunsAs, "k8s-token")
	}
	for i, sa := range sas {
		edge(sa, roles[i%len(roles)], graph.Assumes, "irsa")
	}
	for range s.chains {
		edge(roles[r.IntN(len(roles))], roles[r.IntN(len(roles))], graph.Assumes, "sts")
	}
	for _, role := range roles {
		for range s.readsPerRole {
			j := r.IntN(len(js))
			read := edge(role, js[j], graph.CanRead, "")
			dec := b.Edge(&graph.Edge{From: role, To: keys[j], Kind: graph.CanDecrypt, For: js[j], Verdict: eval.Allow, Confidence: graph.High})
			b.Edge(&graph.Edge{From: role, To: js[j], Kind: graph.CanReadPlaintext, For: graph.NoNode, Verdict: eval.Allow, Confidence: graph.High, Under: []graph.EdgeID{read, dec}})
		}
	}
	g = b.Build()
	for i := range ws {
		n, _ := g.Lookup(model.ID(fmt.Sprintf("w/workload/%d", i)))
		entries = append(entries, n)
	}
	for i := range js {
		n, _ := g.Lookup(model.ID(fmt.Sprintf("jewel/bucket/%d", i)))
		jewels = append(jewels, n)
	}
	return g, entries, jewels
}

func defaultCost(g *graph.Graph) func(graph.EdgeID) int64 {
	costs := map[graph.Kind]int64{graph.RunsAs: 100, graph.CanRead: 1, graph.CanDecrypt: 1, graph.CanEscalate: 3}
	return func(id graph.EdgeID) int64 {
		if c, ok := costs[g.Edge(id).Kind]; ok {
			return c
		}
		return 5
	}
}

// target is the Phase 4 performance target (DESIGN.md §7.4): about 50k
// nodes and 500k edges.
var targetShape = shape{workloads: 30000, accounts: 12000, roles: 6000, jewels: 1000, readsPerRole: 26, chains: 2000}

func BenchmarkAnalyze(b *testing.B) {
	for _, s := range []struct {
		name string
		sh   shape
	}{
		{"small", shape{workloads: 300, accounts: 120, roles: 60, jewels: 50, readsPerRole: 10, chains: 20}},
		{"target", targetShape},
	} {
		g, entries, jewels := synthetic(s.sh, 1)
		b.Run(fmt.Sprintf("%s-%dnodes-%dedges", s.name, g.NumNodes(), g.NumEdges()), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				Analyze(g, entries, jewels, Options{Cost: defaultCost(g)})
			}
		})
	}
}

// TestPerformanceTarget runs the target shape once with -run and a flag-free
// opt-in (CLAPA_PERF=1 in the bench workflow), and reports time and memory.
func TestPerformanceTarget(t *testing.T) {
	if testing.Short() || !perfEnabled() {
		t.Skip("set CLAPA_PERF=1 to run the 50k-node / 500k-edge target")
	}
	g, entries, jewels := synthetic(targetShape, 1)
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now() //nolint:forbidigo // measuring the run itself, not a decision
	pairs := Analyze(g, entries, jewels, Options{Cost: defaultCost(g)})
	elapsed := time.Since(start)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	t.Logf("%d nodes, %d edges, %d entries, %d pairs: %s; %d MiB obtained from the OS (peak bound), %d MiB allocated in total",
		g.NumNodes(), g.NumEdges(), len(entries), len(pairs), elapsed, after.Sys>>20, (after.TotalAlloc-before.TotalAlloc)>>20)
	if after.Sys > 2<<30 {
		t.Errorf("over the 2 GB target: %d MiB", after.Sys>>20)
	}
	if elapsed > time.Minute {
		t.Errorf("over the 60 s target: %s", elapsed)
	}
}

func perfEnabled() bool { return os.Getenv("CLAPA_PERF") == "1" }
