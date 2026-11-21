package app

import (
	"slices"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/remediate"
)

// Scenario 22: role/ops's trust names role/app's ARN in the same account.
// A same-account resource policy naming an IAM role ARN grants on its own
// (DESIGN.md 6, "Same-account effect"), so role/app's sts:AssumeRole is not a
// side of ASSUMES role/app -> role/ops: removing it does not break the edge,
// and the verifier rejects it as a fix (the Phase 6 review's corrected
// derivation of the escalation finding).
func TestSameAccountTrustNamingTheRoleARNMakesTheIdentitySideNonCutting(t *testing.T) {
	const app, ops = "arn:aws:iam::111122223333:role/app", "arn:aws:iam::111122223333:role/ops"
	in, l, a := scanFixture(t, "22_direct_and_escalation/vulnerable", nil)
	g := a.AccessGraph
	found := false
	for i := range g.NumEdges() {
		e := g.Edge(graph.EdgeID(i))
		// The real role, not its "any permission" twin (same identity).
		if e.Kind != graph.Assumes || g.Node(e.From).Kind != model.KindIAMRole || g.Node(e.From).Identity != app || g.Node(e.To).Identity != ops {
			continue
		}
		found = true
		var sides []string
		for _, fx := range e.Fixes {
			sides = append(sides, fx.Side)
		}
		if !slices.Equal(sides, []string{graph.SideTrust}) {
			t.Fatalf("the trust alone grants: the only side is the trust, got %v", sides)
		}
	}
	if !found {
		t.Fatal("no ASSUMES role/app -> role/ops")
	}
	f := findingFor(a, "CLAPA-PATH-002", "arn:aws:s3:::acme-customer-pii")
	if f == nil {
		t.Fatal("no escalation finding")
	}
	// Remove role/app's sts:AssumeRole on role/ops (statement UseOps).
	var edit *remediate.Edit
	for _, ap := range l.Inventory.Policies {
		for _, s := range ap.Doc.Statements() {
			if s.Sid() == "UseOps" {
				edit = &remediate.Edit{Op: remediate.OpRemoveStatement, Policy: ap.Doc.ID(), Index: s.Index()}
			}
		}
	}
	if edit == nil {
		t.Fatal("no UseOps statement")
	}
	plan := &remediate.Plan{Fingerprint: f.Fingerprint, Strategy: remediate.StrategyRootCause, Changes: []remediate.Change{{
		Edge: "ASSUMES " + app + " -> " + ops, Side: graph.SideIdentity, Kind: graph.FixRevoke, Edits: []remediate.Edit{*edit},
	}}}
	r, err := verifyPlan(t.Context(), in, l, a, plan)
	if err != nil {
		t.Fatal(err)
	}
	if r.Memory.OK || !slices.ContainsFunc(r.Memory.Reasons, func(s string) bool { return strings.HasPrefix(s, "the targeted finding ") }) {
		t.Fatalf("removing the identity grant leaves the escalation: the verifier must reject it: %+v", r.Memory)
	}
}
