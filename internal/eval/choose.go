package eval

import (
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/eval/condition"
	"github.com/r3oof-900/darb/internal/model"
)

// maxCombinations bounds the requests one decision tries: beyond it the
// choices are left unknown, so the decision is never less certain than
// without them.
const maxCombinations = 512

// choiceSet is one applicable choice with its options expanded.
type choiceSet struct {
	keys    []string
	options []condition.Option
	reason  string
}

// Evaluate decides req against ps following AWS's documented policy
// evaluation logic (docs/DESIGN.md section 6). It is a pure function:
// statement and policy order never change the result.
//
// Choices of the context (DESIGN.md §6.2) that a policy of ps refers to are
// tried as whole requests: for each undocumented option, the attacker's
// best option; then the undocumented options decide alike, or the decision
// is UNKNOWN at the best of them, naming the keys.
func Evaluate(req *Request, ps *PolicySet) Decision {
	ctx := contextOf(req)
	attacker, undocumented := applicable(ctx, docsOf(ps))
	if !feasible(attacker, undocumented) {
		return evaluateOne(req, ps, ctx)
	}
	var per []Decision
	for _, u := range product(undocumented) {
		cu := apply(ctx, undocumented, u)
		var best *Decision
		for _, a := range product(attacker) {
			d := evaluateOne(req, ps, apply(cu, attacker, a))
			if best == nil || better(&d, best) {
				best = &d
			}
		}
		per = append(per, *best)
	}
	return settle(per, undocumented)
}

// GrantingDetail is Granting with each statement's applicability. With
// choices, a statement grants when it applies under the attacker's option
// for some undocumented option (every one of them must change for the edge
// to break); one that applies under some undocumented options and not
// others is UNKNOWN.
func GrantingDetail(req *Request, docs []*model.PolicyDocument) []GrantDetail {
	ctx := contextOf(req)
	attacker, undocumented := applicable(ctx, docs)
	if !feasible(attacker, undocumented) {
		return grantingOne(req, docs, ctx)
	}
	worlds := grantWorlds(req, docs, ctx, attacker, undocumented)
	var out []GrantDetail
	for _, d := range docs {
		for _, s := range d.Statements() {
			if g, ok := mergeWorlds(worlds, stmtKey{d, s.Index()}, undocumented); ok {
				out = append(out, g)
			}
		}
	}
	return out
}

type stmtKey struct {
	doc *model.PolicyDocument
	idx int
}

// grantWorlds: per undocumented option, the granting statements under the
// attacker's options (the most certain applicability of each).
func grantWorlds(req *Request, docs []*model.PolicyDocument, ctx *condition.Context, attacker, undocumented []choiceSet) []map[stmtKey]GrantDetail {
	var worlds []map[stmtKey]GrantDetail
	for _, u := range product(undocumented) {
		cu := apply(ctx, undocumented, u)
		world := map[stmtKey]GrantDetail{}
		for _, a := range product(attacker) {
			for _, g := range grantingOne(req, docs, apply(cu, attacker, a)) {
				k := stmtKey{g.Doc, g.Statement.Index()}
				if prev, ok := world[k]; !ok || rank(g.Applies) > rank(prev.Applies) {
					world[k] = g
				}
			}
		}
		worlds = append(worlds, world)
	}
	return worlds
}

// mergeWorlds: the statement's grant across the undocumented options; it
// is UNKNOWN when they disagree.
func mergeWorlds(worlds []map[stmtKey]GrantDetail, k stmtKey, undocumented []choiceSet) (GrantDetail, bool) {
	var g GrantDetail
	ranks := map[int]bool{}
	for _, w := range worlds {
		o := w[k] // zero (Doc nil) where it does not grant
		ranks[grantRank(&o)] = true
		if o.Doc != nil && (g.Doc == nil || rank(o.Applies) > rank(g.Applies)) {
			g = o
		}
	}
	if g.Doc == nil {
		return g, false
	}
	if len(ranks) > 1 {
		g.Applies = model.Unknown
		g.Unresolved = append(slices.Clone(g.Unresolved), undocumentedUnresolved(undocumented)...)
	}
	return g, true
}

// grantRank: -1 when the statement does not grant in a world.
func grantRank(g *GrantDetail) int {
	if g.Doc == nil {
		return -1
	}
	return rank(g.Applies)
}

// rank orders a granting statement's applicability (TRUE or UNKNOWN; a
// statement that does not apply is not granting).
func rank(t model.Tri) int {
	if t == model.True {
		return 2
	}
	return 1
}

// better: more access, then an UNKNOWN that only unknown Denies block.
func better(a, b *Decision) bool {
	if a.Verdict.Grants() != b.Verdict.Grants() {
		return a.Verdict.Grants() > b.Verdict.Grants()
	}
	return a.Verdict == Unknown && a.DenyOnly && !b.DenyOnly
}

// settle combines the decisions of the undocumented options.
func settle(per []Decision, undocumented []choiceSet) Decision {
	first := per[0]
	if !slices.ContainsFunc(per[1:], func(d Decision) bool { return d.Verdict != first.Verdict || d.DenyOnly != first.DenyOnly }) {
		return first
	}
	best := &per[0]
	for i := range per {
		if better(&per[i], best) {
			best = &per[i]
		}
	}
	if best.Verdict.Grants() == 0 {
		return *best // no option grants: no access, whichever holds
	}
	out := *best
	out.Verdict = Unknown
	// Only Denies differ between the options: every required allow holds.
	out.DenyOnly = !slices.ContainsFunc(per, func(d Decision) bool {
		return d.Verdict == ImplicitDeny || d.Verdict == Unknown && !d.DenyOnly
	})
	out.Unresolved = append(slices.Clone(out.Unresolved), undocumentedUnresolved(undocumented)...)
	return out
}

func undocumentedUnresolved(sets []choiceSet) []Unresolved {
	out := make([]Unresolved, 0, len(sets))
	for _, s := range sets {
		out = append(out, Unresolved{Element: "Condition", Key: s.keys[0], Reason: s.reason})
	}
	return out
}

// applicable: the context's choices that a policy refers to, options
// expanded, split by who decides them.
func applicable(ctx *condition.Context, docs []*model.PolicyDocument) (attacker, undocumented []choiceSet) {
	refs := conditionValues(docs)
	for _, ch := range ctx.Choices() {
		if !slices.ContainsFunc(ch.Keys, func(k string) bool { _, ok := refs[strings.ToLower(k)]; return ok }) {
			continue
		}
		set := choiceSet{keys: ch.Keys, options: ch.Options, reason: reasonOf(&ch)}
		if ch.Free {
			set.options = freeOptions(&ch, refs[strings.ToLower(ch.Keys[0])])
		}
		if ch.By == condition.Undocumented {
			undocumented = append(undocumented, set)
		} else {
			attacker = append(attacker, set)
		}
	}
	return attacker, undocumented
}

func reasonOf(ch *condition.Choice) string {
	r := "the documentation leaves its value open (" + ch.Source + ")"
	if len(ch.Keys) > 1 {
		r = "decided with " + strings.Join(ch.Keys[1:], " and ") + "; " + r
	}
	return r
}

// freeOptions: the given options, each value a policy compares the key
// with, and the fresh value, without duplicates.
func freeOptions(ch *condition.Choice, values []string) []condition.Option {
	out := slices.Clone(ch.Options)
	seen := map[string]bool{}
	k := ch.Keys[0]
	for _, o := range out {
		if vs, ok := o[k]; ok && len(vs) == 1 {
			seen[vs[0]] = true
		}
	}
	for _, v := range append(slices.Clone(values), ch.Fresh) {
		if v != "" && !seen[v] && !strings.Contains(v, "${") {
			seen[v] = true
			out = append(out, condition.Option{k: {v}})
		}
	}
	return out
}

// conditionValues: every condition key the documents use (lower case), with
// the values they compare it with.
func conditionValues(docs []*model.PolicyDocument) map[string][]string {
	out := map[string][]string{}
	for _, d := range docs {
		for _, s := range d.Statements() {
			for _, c := range s.Conditions() {
				k := strings.ToLower(c.Key())
				out[k] = append(out[k], c.Values()...)
			}
		}
	}
	return out
}

func docsOf(ps *PolicySet) []*model.PolicyDocument {
	out := slices.Concat(ps.Identity, ps.Resource, ps.Session)
	if ps.Boundary != nil {
		out = append(out, ps.Boundary)
	}
	for _, l := range slices.Concat(ps.SCPs, ps.RCPs) {
		out = append(out, l...)
	}
	return out
}

func feasible(attacker, undocumented []choiceSet) bool {
	n := 1
	for _, s := range slices.Concat(attacker, undocumented) {
		n *= len(s.options)
		if n > maxCombinations || len(s.options) == 0 {
			return false
		}
	}
	return len(attacker)+len(undocumented) > 0
}

// product: every combination of one option per set (one empty combination
// for no sets).
func product(sets []choiceSet) [][]condition.Option {
	out := [][]condition.Option{nil}
	for _, s := range sets {
		var next [][]condition.Option
		for _, prefix := range out {
			for _, o := range s.options {
				next = append(next, append(slices.Clone(prefix), o))
			}
		}
		out = next
	}
	return out
}

func apply(ctx *condition.Context, sets []choiceSet, opts []condition.Option) *condition.Context {
	for i, s := range sets {
		ctx = ctx.With(s.keys, opts[i])
	}
	return ctx
}
