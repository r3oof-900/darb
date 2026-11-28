package app

import (
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/access"
	"github.com/r3oof-900/darb/internal/collect/tfraw"
	"github.com/r3oof-900/darb/internal/config"
	"github.com/r3oof-900/darb/internal/coverage"
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
	built := access.Build(inv, &access.Options{Partition: partition(cfg), Jewels: targets, Assume: cfg.Assume, Now: l.Now})
	g := built.Graph
	if edit != nil {
		g = edit(g)
	}
	entries, entryInfo := entryPoints(g, l, *cfg.ThreatModel.AssumeCompromised)
	routes := intendedRoutes(g, inv, cfg, intended)
	uncuttable := intendedEdges(g, routes)
	opts := paths.Options{Cost: costs(g, cfg, uncuttable)}

	jewelNodes := map[graph.NodeID]*model.Resource{}
	var dataJewels []graph.NodeID
	for _, j := range jewels {
		if n, ok := g.Lookup(j.ID()); ok && j.Kind() != model.KindKMSKey {
			jewelNodes[n] = j
			dataJewels = append(dataJewels, n)
		}
	}
	pairs, routeNotes := withoutIntended(paths.Analyze(g, entries, dataJewels, opts), g, cfg, intended, routes)
	in := &rules.Input{Inventory: inv, Graph: g, Pairs: pairs, Entries: entryInfo, Jewels: jewelNodes, Partition: partition(cfg), Cuts: &opts}
	fs := findings.Finish(reg.Evaluate(in), reg)
	a := &Analysis{
		Findings: fs, Notes: slices.Concat(built.Notes, l.Notes, unclassifiedNotes(l.Inventory, cfg), notModelled(l.Inventory), routeNotes, timeNote(l.Inventory, l.Now)),
		Gaps: l.Gaps, Collected: l.Collected,
		IntendedAccess: verifyIntended(g, cfg, intended, routes),
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
