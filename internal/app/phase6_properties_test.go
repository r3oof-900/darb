package app

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/paths"
	"github.com/r3oof-900/darb/internal/remediate"
	"github.com/r3oof-900/darb/internal/rules"
)

// The Phase 6 review's properties of one finding per rule (DESIGN.md §8).

// propertyVariants: every variant whose expected file has a path finding.
func propertyVariants(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(repoRoot(t), "tests", "fixtures", "*", "*", "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range files {
		v := filepath.ToSlash(filepath.Join(filepath.Base(filepath.Dir(filepath.Dir(f))), filepath.Base(filepath.Dir(f))))
		if !strings.HasPrefix(v, "15_") {
			out = append(out, v)
		}
	}
	return out
}

type loadedVariant struct {
	in *Inputs
	l  *Loaded
}

func loadVariants(t *testing.T, variants []string) map[string]loadedVariant {
	t.Helper()
	out := map[string]loadedVariant{}
	for _, v := range variants {
		in := scansFor(t, copyTree(t, filepath.Join(repoRoot(t), "tests", "fixtures", filepath.FromSlash(v))))["normalized.golden.json"]
		l, err := Load(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		out[v] = loadedVariant{in, l}
	}
	return out
}

func analyzed(t interface{ Fatal(...any) }, lv loadedVariant, edit func(*Loaded), g func(*graph.Graph) *graph.Graph) *Analysis {
	l := *lv.l
	inv := *lv.l.Inventory
	l.Inventory = &inv
	if edit != nil {
		edit(&l)
	}
	a, err := analyze(&l, lv.in.Config, DefaultFailOn, g)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var statusRank = map[string]int{rules.StatusUnconfirmed: 0, rules.StatusConfirmedUnlessDenied: 1, rules.StatusConfirmed: 2}

// An unknown policy attached to any role never hides a confirmed finding
// and never changes its fingerprint (rule, entry, jewel); an unknown Allow
// never lowers its status: it adds grants, it removes none. (An unknown
// Deny on a role of the path makes it confirmed_unless_denied, which is
// what that status says, DESIGN.md 6.2.)
func TestPropertyUnknownNeverHidesAConfirmedFinding(t *testing.T) {
	variants := propertyVariants(t)
	loaded := loadVariants(t, variants)
	rapid.Check(t, func(rt *rapid.T) {
		v := rapid.SampledFrom(variants).Draw(rt, "scenario")
		lv := loaded[v]
		var roles []*model.Principal
		for _, p := range lv.l.Inventory.Principals {
			if p.Kind() == model.KindIAMRole {
				roles = append(roles, p)
			}
		}
		if len(roles) == 0 {
			rt.Skip("no role")
		}
		role := rapid.SampledFrom(roles).Draw(rt, "role")
		kind := rapid.SampledFrom([]string{"allow", "deny", "both"}).Draw(rt, "unknown policy")
		before := analyzed(rt, lv, nil, nil)
		after := analyzed(rt, lv, func(l *Loaded) {
			l.Inventory.Policies = append(slices.Clone(l.Inventory.Policies), &model.AttachedPolicy{Target: role.ID(), Doc: unknownPolicy(rt, kind)})
		}, nil)
		got := map[string]*rules.Finding{}
		for i := range after.Findings {
			got[after.Findings[i].Fingerprint] = &after.Findings[i]
		}
		for i := range before.Findings {
			f := &before.Findings[i]
			if f.Kind != rules.KindPath || f.Status != rules.StatusConfirmed {
				continue
			}
			a, ok := got[f.Fingerprint]
			switch {
			case !ok:
				rt.Fatalf("%s: an unknown %s policy on %s hid (or re-fingerprinted) %s %s -> %s", v, kind, role.Identity(), f.Rule, f.Entry, f.Jewel)
			case kind == "allow" && statusRank[a.Status] < statusRank[f.Status]:
				rt.Fatalf("%s: an unknown Allow on %s lowered %s %s -> %s to %s", v, role.Identity(), f.Rule, f.Entry, f.Jewel, a.Status)
			}
		}
	})
}

// edgeStatus and dominated restate DESIGN.md 6.2 and §8 independently of
// the rules package: an edge is confirmed when ALLOW, confirmed unless
// denied when only unknown Denies may block it, otherwise unconfirmed (an
// UNKNOWN precondition too; a derived edge, its weakest underlying edge).
func edgeStatus(g *graph.Graph, id graph.EdgeID) int {
	e := g.Edge(id)
	s := 2
	if e.Precondition != nil && e.Precondition.State != model.True {
		s = 0
	}
	if len(e.Under) > 0 {
		for _, u := range e.Under {
			s = min(s, edgeStatus(g, u))
		}
		return s
	}
	switch {
	case e.Verdict == eval.Allow:
	case e.DenyOnly:
		s = min(s, 1)
	default:
		s = 0
	}
	return s
}

// dominated: the source of the first escalation reaches the jewel without
// one, through edges at least as certain as the rest of the path.
func dominated(g *graph.Graph, path []graph.EdgeID, jewel graph.NodeID) bool {
	k := slices.IndexFunc(path, func(id graph.EdgeID) bool { return g.Edge(id).Kind == graph.CanEscalate })
	if k < 0 {
		return false
	}
	suffix := 2
	for _, id := range path[k:] {
		suffix = min(suffix, edgeStatus(g, id))
	}
	return paths.ReachesDirect(g, path, k, jewel, func(id graph.EdgeID) bool { return edgeStatus(g, id) >= suffix })
}

// No escalation finding has a dominated path (DESIGN.md §8): in every
// scenario, and with an unknown policy attached to any role.
func TestPropertyNoEscalationFindingIsDominated(t *testing.T) {
	variants := propertyVariants(t)
	loaded := loadVariants(t, variants)
	check := func(t interface{ Fatalf(string, ...any) }, v string, a *Analysis) {
		g := a.AccessGraph
		for i := range a.Findings {
			f := &a.Findings[i]
			if f.Rule != "DARB-PATH-002" {
				continue
			}
			jewel, _ := g.Lookup(f.JewelID)
			if dominated(g, f.PathEdges, jewel) {
				t.Fatalf("%s: %s -> %s reports a dominated escalation: %v", v, f.Entry, f.Jewel, f.Path)
			}
		}
	}
	for _, v := range variants {
		check(t, v, analyzed(t, loaded[v], nil, nil))
	}
	rapid.Check(t, func(rt *rapid.T) {
		v := rapid.SampledFrom(variants).Draw(rt, "scenario")
		lv := loaded[v]
		var roles []*model.Principal
		for _, p := range lv.l.Inventory.Principals {
			if p.Kind() == model.KindIAMRole {
				roles = append(roles, p)
			}
		}
		if len(roles) == 0 {
			rt.Skip("no role")
		}
		role := rapid.SampledFrom(roles).Draw(rt, "role")
		check(rt, v, analyzed(rt, lv, func(l *Loaded) {
			l.Inventory.Policies = append(slices.Clone(l.Inventory.Policies), &model.AttachedPolicy{Target: role.ID(), Doc: unknownPolicy(rt, "allow")})
		}, nil))
	})
}

// Applying a finding's cut in memory (its chokepoint edges gone from the
// graph) leaves no new finding for the same (entry, jewel): the cut breaks
// the paths it dominates too, so no escalation appears in their place.
func TestPropertyCutLeavesNoNewFindingForThePair(t *testing.T) {
	variants := propertyVariants(t)
	loaded := loadVariants(t, variants)
	checked := 0
	for _, v := range variants {
		a := analyzed(t, loaded[v], nil, nil)
		for i := range a.Findings {
			f := &a.Findings[i]
			if f.Kind != rules.KindPath || !f.CutFinite() {
				continue
			}
			before := map[string]bool{}
			for _, o := range a.Findings {
				if o.EntryID == f.EntryID && o.JewelID == f.JewelID {
					before[o.Fingerprint] = true
				}
			}
			cut := map[graph.EdgeID]bool{}
			for _, id := range slices.Concat(f.ChokepointEdge, f.SharedEdges) {
				cut[id] = true
			}
			after := analyzed(t, loaded[v], nil, func(g *graph.Graph) *graph.Graph { return g.Without(cut) })
			for _, o := range after.Findings {
				if o.EntryID == f.EntryID && o.JewelID == f.JewelID && !before[o.Fingerprint] {
					t.Errorf("%s: the cut of %s %s -> %s (%v) leaves a new %s", v, f.Rule, f.Entry, f.Jewel, f.Chokepoints, o.Rule)
				}
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no cut was checked")
	}
}

// Scenario 22's dominance variant: role/app reads the data and could rewrite
// its own policy. Cutting the decrypt alone would make that escalation no
// longer dominated, a new DARB-PATH-002 for the pair: verification rejects
// it. The finding's cut (the decrypt and the escalation) is accepted.
func TestDominatedPathsStayInTheCut(t *testing.T) {
	in, l, a := scanFixture(t, "22_direct_and_escalation/dominance", nil)
	f := findingFor(a, "DARB-PATH-001", "arn:aws:s3:::acme-customer-pii")
	if f == nil || len(f.ChokepointEdge) != 2 {
		t.Fatalf("the cut is the decrypt and the escalation: %+v", f)
	}
	g := a.AccessGraph
	var decrypt graph.EdgeID = -1
	for i, id := range f.ChokepointEdge {
		if g.Edge(id).Kind != graph.CanDecrypt {
			continue
		}
		decrypt = id
		fx := &g.Edge(id).Fixes[f.ChokepointFix[i]]
		c := remediate.ForEdge(&remediate.Input{Inventory: l.Inventory, Graph: g, Intended: a.intended}, id, fx)
		plan := &remediate.Plan{Fingerprint: f.Fingerprint, Strategy: remediate.StrategyMitigation, Changes: []remediate.Change{c}}
		r, err := verifyPlan(t.Context(), in, l, a, plan)
		if err != nil {
			t.Fatal(err)
		}
		if r.Memory.OK || !slices.ContainsFunc(r.Memory.Reasons, func(s string) bool { return strings.HasPrefix(s, "a new finding appears") }) {
			t.Fatalf("cutting the decrypt alone must be rejected (a new escalation finding): %+v", r.Memory)
		}
	}
	if decrypt < 0 {
		t.Fatal("no decrypt in the cut")
	}
	r, err := Remediate(t.Context(), in, l, a, f.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Accepted() {
		t.Fatalf("the finding's own cut is accepted: memory %v, files %v", r.Memory.Reasons, r.Files.Reasons)
	}
}
