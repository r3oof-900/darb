package graph

import (
	"fmt"
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/model"
)

// Undecided says what would decide an UNKNOWN path: the context keys a
// condition needs (set them under assume: in clapa.yaml), the values that
// are not known statically (scan a plan), the preconditions to state.
func (g *Graph) Undecided(path []EdgeID) []string {
	var out []string
	add := func(s string) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	var visit func(id EdgeID)
	visit = func(id EdgeID) {
		e := g.Edge(id)
		for _, u := range e.Under {
			visit(u)
		}
		if e.Precondition != nil && e.Precondition.State == model.Unknown {
			add("state whether " + e.Precondition.Reason + " (" + g.Describe(id) + ")")
		}
		if e.Verdict != eval.Unknown {
			return
		}
		for _, u := range e.Unresolved {
			add(missingOf(&u))
		}
		if len(e.Unresolved) == 0 && len(e.Under) == 0 {
			from, to := g.Node(e.From).Identity, g.Node(e.To).Identity
			if model.ContainsUnresolved(from) || model.ContainsUnresolved(to) {
				add("scan a Terraform plan (--plan): " + g.Describe(id) + " names a value that is not known statically")
			} else {
				add("decide " + g.Describe(id) + ": " + strings.Join(e.Evidence, "; "))
			}
		}
	}
	for _, id := range path {
		visit(id)
	}
	return out
}

// missingOf says what decides one undecided element: a context key to
// assume, or a value a plan would resolve.
func missingOf(u *Unknown) string {
	if u.Element == "Condition" && strings.Contains(u.Key, ":") && !model.ContainsUnresolved(u.Key) {
		return fmt.Sprintf("set `assume: {%q: [...]}` in clapa.yaml: %s conditions on %s, whose value is not in the input (%s)",
			u.Key, u.Policy, u.Key, u.Reason)
	}
	if name, ok := awsManagedPolicy(u.Policy); ok {
		return fmt.Sprintf("the AWS managed policy %s is not in the managed policy snapshot, so what it grants is unknown: "+
			"managed policy snapshot is incomplete: run tools/refresh-managed-policies", name)
	}
	return fmt.Sprintf("decide %s %s of %s: %s; a Terraform plan (--plan) resolves values that are not known statically",
		u.Element, u.Key, u.Policy, u.Reason)
}

// awsManagedPolicy returns the name of an AWS managed policy ARN
// (arn:<partition>:iam::aws:policy/<path><name>).
func awsManagedPolicy(policyARN string) (string, bool) {
	_, rest, ok := strings.Cut(policyARN, ":iam::aws:policy/")
	if !ok || !strings.HasPrefix(policyARN, "arn:") || rest == "" {
		return "", false
	}
	return rest[strings.LastIndex(rest, "/")+1:], true
}
