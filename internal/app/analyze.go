package app

import (
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/access"
	"github.com/r3oof-900/darb/internal/collect/tfraw"
	"github.com/r3oof-900/darb/internal/config"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/findings"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/paths"
	"github.com/r3oof-900/darb/internal/rules"
	"github.com/r3oof-900/darb/internal/rules/catalog"
	"github.com/r3oof-900/darb/internal/scoring"
	"github.com/r3oof-900/darb/pkg/schema"
)

// DefaultFailOn is the default --fail-on threshold (DESIGN.md §8.2).
const DefaultFailOn = "high"

// IntendedResult is the verification of one intended_access entry.
type IntendedResult struct {
	Principal string `json:"principal"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	// Status: "verified" (a confirmed path), "unconfirmed" (only paths that
	// rest on UNKNOWN), "not-satisfied" (no path: the declared access does
	// not work as configured), "not-modelled" (an action or
	// resource the engine does not evaluate).
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Analysis is the result of a scan.
type Analysis struct {
	Findings       []rules.Finding  `json:"findings"`
	IntendedAccess []IntendedResult `json:"intended_access"`
	Notes          []access.Note    `json:"coverage_notes"`
	Gaps           []coverage.Gap   `json:"gaps"`
	Collected      int              `json:"collected"`
	GapsCounted    int              `json:"gaps_over_tolerance"`
	// Inputs: what was scanned, with digests (Loaded.Inputs).
	Inputs         []schema.ScannedInput `json:"-"`
	ExitCode       int                   `json:"exit_code"`
	Graph          GraphStats            `json:"graph"`
	CatalogVersion string                `json:"rule_catalog_version"`
	// Triage results (ApplyTriage): suppressed findings, expired
	// suppressions, the baseline comparison.
	Suppressed  []schema.SuppressedFinding  `json:"-"`
	Expired     []schema.ExpiredSuppression `json:"-"`
	Baseline    *schema.Baseline            `json:"-"`
	Registry    *rules.Registry             `json:"-"`
	AccessGraph *graph.Graph                `json:"-"`
	// intended: the edges on the paths of declared intended access (the
	// root-cause fixes are narrowed to what they use).
	intended map[graph.EdgeID]bool
}

// GraphStats summarise the access graph.
type GraphStats struct {
	Nodes int `json:"nodes"`
	Edges int `json:"edges"`
	Pairs int `json:"entry_jewel_pairs"`
}

// Analyze builds the access graph, searches paths and runs every rule.
func Analyze(l *Loaded, cfg *config.Config, failOn string) (*Analysis, error) {
	return analyze(l, cfg, failOn, nil)
}

// analyze is Analyze with an optional change to the access graph before the
// paths are searched (a test applies a finding's cut in memory).
func analyze(l *Loaded, cfg *config.Config, failOn string, edit func(*graph.Graph) *graph.Graph) (*Analysis, error) {
	reg, err := catalog.New()
	if err != nil {
		return nil, err
	}
	if l.Intended != nil {
		resolved := *cfg
		resolved.IntendedAccess = l.Intended
		cfg = &resolved
	}
	inv := l.Inventory
	var jewels, targets []*model.Resource
	for _, r := range inv.Resources {
		if class, _ := r.Classification(); class != "" {
			jewels = append(jewels, r)
		}
	}
	targets = append(targets, jewels...)
	intended := intendedTargets(inv, cfg)
	for _, r := range intended {
		if r != nil && !slices.Contains(targets, r) {
			targets = append(targets, r)
		}
	}
	built := access.Build(inv, &access.Options{Partition: partition(cfg), Jewels: targets, Assume: cfg.Assume})
	g := built.Graph
	if edit != nil {
		g = edit(g)
	}
	entries, entryInfo := entryPoints(g, l, *cfg.ThreatModel.AssumeCompromised)
	uncuttable := intendedEdges(g, cfg, intended)
	opts := paths.Options{Cost: costs(g, cfg, uncuttable)}

	jewelNodes := map[graph.NodeID]*model.Resource{}
	var dataJewels []graph.NodeID
	for _, j := range jewels {
		if n, ok := g.Lookup(j.ID()); ok && j.Kind() != model.KindKMSKey {
			jewelNodes[n] = j
			dataJewels = append(dataJewels, n)
		}
	}
	pairs := paths.Analyze(g, entries, dataJewels, opts)
	in := &rules.Input{Inventory: inv, Graph: g, Pairs: pairs, Entries: entryInfo, Jewels: jewelNodes, Partition: partition(cfg), Cuts: &opts}
	fs := findings.Finish(reg.Evaluate(in), reg)
	a := &Analysis{
		Findings: fs, Notes: slices.Concat(built.Notes, l.Notes, notModelled(l.Inventory)), Gaps: l.Gaps, Collected: l.Collected,
		IntendedAccess: verifyIntended(g, cfg, intended, entries, opts),
		Graph:          GraphStats{Nodes: g.NumNodes(), Edges: g.NumEdges(), Pairs: len(pairs)},
		CatalogVersion: catalog.Version, Registry: reg, AccessGraph: g, intended: uncuttable, Inputs: l.Inputs,
	}
	a.GapsCounted = gapsOverTolerance(l.Gaps, cfg)
	a.ExitCode = findings.ExitCode(fs, failOn, l.Collected, a.GapsCounted)
	return a, nil
}

func partition(cfg *config.Config) string {
	if cfg.Terraform.Partition != "" {
		return cfg.Terraform.Partition
	}
	return "aws"
}

// entryPoints: every entry workload, plus the anonymous principal when the
// graph has it (a public grant). Without assume-compromised, the attacker
// comes from the internet: the internet node is the entry and reaches the
// publicly exposed workloads through EXPOSED_TO, which the cut may then
// choose; a privately exposed workload (an internal load balancer) stays an
// entry of its own. With assume-compromised every pod is an entry already,
// so EXPOSED_TO is never on a path.
func entryPoints(g *graph.Graph, l *Loaded, assumeCompromised bool) (nodes []graph.NodeID, info map[graph.NodeID]rules.Entry) {
	info = map[graph.NodeID]rules.Entry{}
	internet, viaInternet := g.Lookup(access.InternetID())
	if viaInternet && !assumeCompromised {
		info[internet] = rules.Entry{Reason: "internet", Public: model.True, Exposure: scoring.Exposure("anonymous", model.True)}
	}
	for _, e := range l.EntryPoints {
		n, ok := g.Lookup(e.Workload)
		if !ok || viaInternet && !assumeCompromised && e.Public != model.False && strings.HasPrefix(e.Reason, "exposed:") {
			continue
		}
		exp := scoring.Exposure(e.Reason, e.Public)
		if prev, seen := info[n]; !seen || exp > prev.Exposure {
			info[n] = rules.Entry{Reason: e.Reason, Public: e.Public, Exposure: exp}
		}
	}
	if n, ok := g.Lookup(access.AnonymousID()); ok {
		info[n] = rules.Entry{Reason: "anonymous", Public: model.True, Exposure: scoring.Exposure("anonymous", model.True)}
	}
	nodes = make([]graph.NodeID, 0, len(info))
	for n := range info {
		nodes = append(nodes, n)
	}
	slices.Sort(nodes)
	return nodes, info
}

// costs: SCORING.md §4 defaults, darb.yaml overrides per kind, and
// uncuttable edges (configured, or on a path of declared intended access).
func costs(g *graph.Graph, cfg *config.Config, uncuttable map[graph.EdgeID]bool) func(graph.EdgeID) int64 {
	return func(id graph.EdgeID) int64 {
		e := g.Edge(id)
		if uncuttable[id] {
			return paths.Uncuttable
		}
		for _, u := range cfg.Remediation.UncuttableEdges {
			if u.Kind == string(e.Kind) && u.From == g.Node(e.From).Identity && u.To == g.Node(e.To).Identity {
				return paths.Uncuttable
			}
		}
		if len(e.Fixes) == 0 {
			return paths.Uncuttable // no single change breaks it (DESIGN.md §7.4)
		}
		if c, ok := cfg.Remediation.CutCosts[string(e.Kind)]; ok {
			return int64(c)
		}
		return paths.Default // priced from its fixes: sides, detaches, resolve steps (SCORING.md §4)
	}
}

// intendedTargets resolves each intended_access resource to a bucket of the
// inventory ("arn:aws:s3:::B/*" names bucket B); nil when not modelled.
func intendedTargets(inv *model.Inventory, cfg *config.Config) []*model.Resource {
	out := make([]*model.Resource, len(cfg.IntendedAccess))
	for i, ia := range cfg.IntendedAccess {
		if ia.Action != "s3:GetObject" {
			continue
		}
		bucket, _, _ := strings.Cut(ia.Resource, "/")
		for _, r := range inv.Resources {
			if r.ARN() == bucket && r.Kind() == model.KindS3Bucket {
				out[i] = r
			}
		}
	}
	return out
}

// intendedEdges: every edge on a path that realises an intended access is
// uncuttable (SCORING.md §4).
func intendedEdges(g *graph.Graph, cfg *config.Config, targets []*model.Resource) map[graph.EdgeID]bool {
	out := map[graph.EdgeID]bool{}
	for i, ia := range cfg.IntendedAccess {
		from, ok1 := g.Lookup(model.NewID(model.KindK8sWorkload, ia.Principal))
		if targets[i] == nil || !ok1 {
			continue
		}
		to, ok2 := g.Lookup(targets[i].ID())
		if !ok2 {
			continue
		}
		pairs := paths.Analyze(g, []graph.NodeID{from}, []graph.NodeID{to}, paths.Options{Cost: func(graph.EdgeID) int64 { return 1 }})
		for _, p := range pairs {
			markPaths(g, p.Paths, out)
		}
	}
	return out
}

// markPaths marks every edge of the paths, and the edges a derived edge
// stands for.
func markPaths(g *graph.Graph, ps []paths.Path, out map[graph.EdgeID]bool) {
	for _, path := range ps {
		for _, id := range path {
			out[id] = true
			for _, u := range g.Edge(id).Under {
				out[u] = true
			}
		}
	}
}

func verifyIntended(g *graph.Graph, cfg *config.Config, targets []*model.Resource, _ []graph.NodeID, opts paths.Options) []IntendedResult {
	out := []IntendedResult{}
	for i, ia := range cfg.IntendedAccess {
		r := IntendedResult{Principal: ia.Principal, Action: ia.Action, Resource: ia.Resource, Status: "not-satisfied"}
		from, ok := g.Lookup(model.NewID(model.KindK8sWorkload, ia.Principal))
		switch {
		case targets[i] == nil:
			r.Status, r.Detail = "not-modelled", "only s3:GetObject on a bucket in the input is verified"
		case !ok:
			r.Detail = "the principal is not a workload in the input"
		default:
			to, _ := g.Lookup(targets[i].ID())
			for _, p := range paths.Analyze(g, []graph.NodeID{from}, []graph.NodeID{to}, opts) {
				r.Status = "unconfirmed"
				for _, path := range p.Paths {
					if confirmed(g, path) {
						r.Status = "verified"
					}
				}
			}
		}
		out = append(out, r)
	}
	return out
}

func confirmed(g *graph.Graph, path paths.Path) bool {
	for _, id := range path {
		e := g.Edge(id)
		if e.Verdict != eval.Allow || (e.Precondition != nil && e.Precondition.State != model.True) {
			return false
		}
	}
	return true
}

// gapsOverTolerance counts gaps beyond the per-kind tolerance (default 0).
// Plan attributes the provider computes are informational: no decision
// rests on them unless an edge does, which then carries its own UNKNOWN.
func gapsOverTolerance(gaps []coverage.Gap, cfg *config.Config) int {
	count := map[coverage.Kind]int{}
	for i := range gaps {
		if strings.Contains(gaps[i].Detail, tfraw.ReasonComputed) {
			continue
		}
		count[gaps[i].Kind]++
	}
	over := 0
	for k, n := range count {
		if n > cfg.Coverage.Tolerance[string(k)] {
			over += n - cfg.Coverage.Tolerance[string(k)]
		}
	}
	return over
}
