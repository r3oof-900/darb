package rules

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/paths"
	"github.com/r3oof-900/clapa/internal/scoring"
)

// SourceOf returns where a node of the inventory is defined.
func SourceOf(inv *model.Inventory, id model.ID) model.SourceLocation {
	for _, w := range inv.Workloads {
		if w.ID() == id {
			return *w.Source()
		}
	}
	for _, r := range inv.Resources {
		if r.ID() == id {
			return *r.Source()
		}
	}
	for _, p := range inv.Principals {
		if p.ID() == id {
			return *p.Source()
		}
	}
	return model.SourceLocation{}
}

// Kind of rule.
const (
	KindPath    = "path"
	KindPosture = "posture"
)

// Reference is a documentation link of a rule.
type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Meta describes a rule (DESIGN.md §8).
type Meta struct {
	ID         string      `json:"id"`
	Version    string      `json:"version"` // semver
	Kind       string      `json:"kind"`
	Title      string      `json:"title"`
	Rationale  string      `json:"rationale"`
	Base       int         `json:"base,omitempty"` // posture base severity (SCORING.md §2)
	Techniques []string    `json:"attack_techniques"`
	References []Reference `json:"references"`
	// Fixtures that must make the rule fire and must not.
	Failing []string `json:"failing_fixtures"`
	Passing []string `json:"passing_fixtures"`
}

// Major returns the major version (the part of the version in fingerprints).
func (m *Meta) Major() string {
	for i, c := range m.Version {
		if c == '.' {
			return m.Version[:i]
		}
	}
	return m.Version
}

// Entry is an entry point of the graph.
type Entry struct {
	Reason   string
	Public   model.Tri
	Exposure int
}

// Input is what every rule sees. Rules are pure functions of it.
type Input struct {
	Inventory *model.Inventory
	Graph     *graph.Graph
	Pairs     []paths.Pair
	Entries   map[graph.NodeID]Entry
	Jewels    map[graph.NodeID]*model.Resource
	Partition string
}

// Finding is one result of one rule.
type Finding struct {
	Rule    string `json:"rule"`
	Version string `json:"rule_version"`
	Kind    string `json:"kind"`
	Title   string `json:"title"`
	// Path findings.
	Entry     string          `json:"entry,omitempty"`
	Jewel     string          `json:"jewel,omitempty"`
	EntryID   model.ID        `json:"-"`
	JewelID   model.ID        `json:"-"`
	Path      []string        `json:"path,omitempty"`
	PathEdges []graph.EdgeID  `json:"-"`
	Paths     int             `json:"paths_found,omitempty"`
	Truncated bool            `json:"paths_truncated,omitempty"`
	Factors   scoring.Factors `json:"factors"`
	Confirmed bool            `json:"confirmed"`
	// Status: StatusConfirmed, StatusConfirmedUnlessDenied or
	// StatusUnconfirmed (DESIGN.md 6.2); the severity is the worst case
	// whatever the status.
	Status     string `json:"status"`
	Confidence string `json:"confidence"`
	// Undecided: for an unconfirmed path, what would decide it (a context
	// key to assume, a value a plan resolves, a precondition to state).
	Undecided []string `json:"undecided,omitempty"`
	// Chokepoints: the cheapest fix (the weighted min cut).
	Chokepoints    []string       `json:"chokepoints,omitempty"`
	ChokepointIDs  []model.ID     `json:"-"`
	CutCost        int64          `json:"cut_cost,omitempty"`
	NoFix          bool           `json:"no_fix_within_constraints,omitempty"`
	Alternative    []string       `json:"alternative_fix,omitempty"`
	ChokepointEdge []graph.EdgeID `json:"-"`
	// Fix: the side of each chokepoint edge the cut chose, its cheapest fix;
	// OtherSideFix: the other sides that also break that edge, dearer
	// (SCORING.md §4).
	Fix          []FixStep `json:"fix,omitempty"`
	OtherSideFix []FixStep `json:"other_side_fix,omitempty"`
	// AlternativeDetail: the cheapest fix of each alternative_fix edge.
	AlternativeDetail []FixStep `json:"alternative_fix_detail,omitempty"`
	// SharedFix: resources one change to whose policy breaks two or more
	// chokepoint edges. Shared fixes are priced in Phase 5; until then the
	// cut cost counts edges and is not the size of the fix.
	SharedFix []string `json:"shared_fix_possible,omitempty"`
	// Posture findings.
	Resource   string   `json:"resource,omitempty"`
	ResourceID model.ID `json:"-"`
	// Both.
	// Location: where to look — the entry workload of a path (the jewel for
	// a public path), the resource of a posture finding.
	Location     model.SourceLocation `json:"-"`
	DefaultsUsed []string             `json:"defaults_used"`
	Evidence     []string             `json:"evidence,omitempty"`
	Fingerprint  string               `json:"fingerprint"`
}

// FixStep is one change that breaks one edge.
type FixStep struct {
	Edge string `json:"edge"`
	Side string `json:"side"`
	// Kind: "narrow" (make a broad grant specific) or "revoke" (remove an
	// explicit grant; confirm it is not needed), SCORING.md §4.1.
	Kind   string `json:"fix_kind"`
	Policy string `json:"policy"`
	Cost   int64  `json:"cost"`
}

// Rule is a rule: metadata plus a pure evaluation.
type Rule interface {
	Meta() Meta
	Evaluate(in *Input) []Finding
}

// ErrDuplicateRule is returned when two rules share an ID.
var ErrDuplicateRule = errors.New("rules: duplicate rule ID")

// Registry is an explicit, immutable set of rules (no package-level state).
type Registry struct {
	rules []Rule
}

// NewRegistry builds a registry; rule IDs must be unique.
func NewRegistry(rs ...Rule) (*Registry, error) {
	seen := map[string]bool{}
	for _, r := range rs {
		id := r.Meta().ID
		if seen[id] {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateRule, id)
		}
		seen[id] = true
	}
	sorted := slices.Clone(rs)
	slices.SortFunc(sorted, func(a, b Rule) int { return cmp.Compare(a.Meta().ID, b.Meta().ID) })
	return &Registry{rules: sorted}, nil
}

// Rules returns the rules, sorted by ID.
func (r *Registry) Rules() []Rule { return slices.Clone(r.rules) }

// Get returns a rule by ID.
func (r *Registry) Get(id string) (Rule, bool) {
	for _, rule := range r.rules {
		if rule.Meta().ID == id {
			return rule, true
		}
	}
	return nil, false
}

// Evaluate runs every rule and returns the findings in a deterministic order.
func (r *Registry) Evaluate(in *Input) []Finding {
	var out []Finding
	for _, rule := range r.rules {
		m := rule.Meta()
		fs := rule.Evaluate(in)
		for i := range fs {
			f := &fs[i]
			f.Rule, f.Version, f.Kind, f.Title = m.ID, m.Version, m.Kind, m.Title
			if f.DefaultsUsed == nil {
				f.DefaultsUsed = []string{}
			}
		}
		out = append(out, fs...)
	}
	slices.SortFunc(out, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(a.Rule, b.Rule), cmp.Compare(a.Entry, b.Entry), cmp.Compare(a.Jewel, b.Jewel), cmp.Compare(a.Resource, b.Resource))
	})
	return out
}

// Finding statuses (DESIGN.md 6.2).
const (
	// StatusConfirmed: no UNKNOWN decides the finding.
	StatusConfirmed = "confirmed"
	// StatusConfirmedUnlessDenied: the only UNKNOWNs are possible Denies.
	StatusConfirmedUnlessDenied = "confirmed_unless_denied"
	// StatusUnconfirmed: the finding needs an unknown allow, an UNKNOWN
	// precondition or an UNKNOWN fact to hold.
	StatusUnconfirmed = "unconfirmed"
)

// Weaker returns the less certain of two statuses.
func Weaker(a, b string) string {
	rank := func(s string) int {
		switch s {
		case StatusConfirmed:
			return 0
		case StatusConfirmedUnlessDenied:
			return 1
		}
		return 2
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}
