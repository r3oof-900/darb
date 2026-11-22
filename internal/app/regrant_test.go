package app

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/rules"
)

// The re-grant rule (SCORING.md §4): after a principal that can give itself
// the access back (rewrite the target's resource policy, the key's policy or
// a KMS grant, or its own policies), no identity-side cut counts, and a
// resource side it can rewrite does not count either; the cut moves before it.

const (
	apiRole   = "arn:aws:iam::111122223333:role/payments-api"
	piiBucket = "arn:aws:s3:::acme-customer-pii"
)

func edgeBetween(t *testing.T, g *graph.Graph, kind graph.Kind, from, to string) *graph.Edge {
	t.Helper()
	for i := range g.NumEdges() {
		e := g.Edge(graph.EdgeID(i))
		if e.Kind == kind && g.Node(e.From).Identity == from && g.Node(e.To).Identity == to {
			return e
		}
	}
	t.Fatalf("no %s edge %s -> %s", kind, from, to)
	return nil
}

func hasSide(e *graph.Edge, side string) bool {
	for i := range e.Fixes {
		if e.Fixes[i].Side == side {
			return true
		}
	}
	return false
}

// addStatement adds a statement to payments-api's inline policy (scenario 1).
func addStatement(t *testing.T, dir, statement string) {
	t.Helper()
	replaceIn(t, filepath.Join(dir, "terraform", "role.tf"),
		`{ Sid = "DecryptAnything", Effect = "Allow", Action = ["kms:Decrypt"], Resource = "*" },`,
		`{ Sid = "DecryptAnything", Effect = "Allow", Action = ["kms:Decrypt"], Resource = "*" }, `+statement+`,`)
}

func TestRegrantRemovesIdentitySide(t *testing.T) {
	base := analyzeVariant(t, "01_classic/vulnerable", nil)
	if read := edgeBetween(t, base.AccessGraph, graph.CanRead, apiRole, piiBucket); !hasSide(read, graph.SideIdentity) {
		t.Fatalf("baseline: the read has an identity-side fix: %+v", read.Fixes)
	}

	// The role can rewrite the bucket policy: cutting its s3:GetObject does
	// not hold (it writes the grant back on the bucket), nor does narrowing
	// the bucket policy. The read is uncuttable; the cut takes the decrypt.
	putPolicy := `{ Sid = "Rewrite", Effect = "Allow", Action = ["s3:PutBucketPolicy"], Resource = aws_s3_bucket.customer_pii.arn }`
	a := analyzeVariant(t, "01_classic/vulnerable", func(dir string) { addStatement(t, dir, putPolicy) })
	if read := edgeBetween(t, a.AccessGraph, graph.CanRead, apiRole, piiBucket); len(read.Fixes) != 0 {
		t.Fatalf("PutBucketPolicy: the read must have no fix, got %+v", read.Fixes)
	}
	f := findingFor(a, "DARB-PATH-001", piiBucket)
	if f == nil || len(f.Fix) != 1 || !strings.HasPrefix(f.Fix[0].Edge, "CAN_DECRYPT") || f.Fix[0].Side != graph.SideIdentity {
		t.Fatalf("PutBucketPolicy: the cut must be the decrypt's identity side: %+v", f)
	}

	// It can also create a KMS grant: nothing after the role is cuttable,
	// so the cut is the hop into the role, never an identity side after it.
	grant := `{ Sid = "Grant", Effect = "Allow", Action = ["kms:CreateGrant"], Resource = "*" }`
	a = analyzeVariant(t, "01_classic/vulnerable", func(dir string) {
		addStatement(t, dir, putPolicy)
		addStatement(t, dir, grant)
	})
	g := a.AccessGraph
	for i := range g.NumEdges() {
		e := g.Edge(graph.EdgeID(i))
		if g.Node(e.From).Identity == apiRole && (e.Kind == graph.CanRead || e.Kind == graph.CanDecrypt) && len(e.Fixes) != 0 {
			t.Errorf("after a re-granting role no fix counts: %s %+v", g.Describe(graph.EdgeID(i)), e.Fixes)
		}
	}
	f = findingFor(a, "DARB-PATH-001", piiBucket)
	if f == nil || len(f.Chokepoints) != 1 || f.Chokepoints[0] != "ASSUMES k8s:arn:aws:eks:us-east-1:111122223333:cluster/prod/payments/ServiceAccount/api -> "+apiRole {
		t.Fatalf("PutBucketPolicy + CreateGrant: the cut must be the hop into the role: %+v", f)
	}
}

// Scenario 6: analytics-admin can rewrite its own policies, the warehouse
// key's policy and the bucket's. With the hop into it declared uncuttable,
// a cut after it (Phase 6 review, SCORING.md 4.1-4.2) must break its
// escalation too, never its read alone, and AdministratorAccess, which AWS
// owns, is detached, never narrowed: one change for every edge it grants.
func TestCutAfterSelfModifyingRoleDetaches(t *testing.T) {
	const admin = "arn:aws:iam::444455556666:role/analytics-admin"
	a := analyzeVariant(t, "06_role_chain_cross_account/vulnerable", func(dir string) {
		appendConfig(t, dir, "remediation:", "  uncuttable_edges:",
			"    - {kind: ASSUMES, from: \""+apiRole+"\", to: \""+admin+"\", reason: test}")
	})
	f := findingFor(a, "DARB-PATH-001", "arn:aws:s3:::acme-analytics-warehouse")
	if f == nil || len(f.Chokepoints) == 0 {
		t.Fatalf("a cut must exist: %+v", f)
	}
	after := slices.ContainsFunc(f.Chokepoints, func(c string) bool { return strings.Contains(c, admin+" ->") })
	escalation := slices.ContainsFunc(f.Chokepoints, func(c string) bool {
		return strings.HasPrefix(c, "CAN_ESCALATE[iam:modify-policy] "+admin+" ->")
	})
	if after && !escalation {
		t.Errorf("a cut after the self-modifying role must break its escalation: %v", f.Chokepoints)
	}
	for _, s := range f.Fix {
		if strings.Contains(s.Edge, admin+" ->") && (s.Kind != "revoke" || s.Policy != "arn:aws:iam::aws:policy/AdministratorAccess" || s.Cost != 4) {
			t.Errorf("AdministratorAccess is detached (identity, revoke, 4), never narrowed: %+v", s)
		}
	}
	if after && f.CutCost != 4 {
		t.Errorf("one detach for every edge it grants: cut cost %d, want 4", f.CutCost)
	}
}

// appendConfig adds YAML lines to the end of the copy's darb.yaml.
func appendConfig(t *testing.T, dir string, lines ...string) {
	t.Helper()
	file := filepath.Join(dir, "darb.yaml")
	data, err := os.ReadFile(file) //nolint:gosec // G304: inside the test's temp copy.
	if err != nil {
		t.Fatal(err)
	}
	extra := strings.Join(append(lines, ""), string(rune(10)))
	if err := os.WriteFile(file, append(data, extra...), 0o600); err != nil { //nolint:gosec // G703: temp copy.
		t.Fatal(err)
	}
}

// intended_access is the strongest constraint (SCORING.md §4): with the api
// workload's read of the PII bucket declared intended, no edge on its path
// is cut, not even the cheapest (the broad decrypt, narrow, cost 1). The
// declared pair itself is not reported (decided after v0.1.0-rc.1); in
// scenario 8, ci-runner reaches the bucket through api's role (creating a
// pod as api, DARB-PATH-002), and its cut must leave api's grants alone.
func TestIntendedAccessIsNeverCut(t *testing.T) {
	const ci = "k8s:arn:aws:eks:us-east-1:111122223333:cluster/prod/payments/Deployment/ci-runner"
	byEntry := func(a *Analysis, entry string) *rules.Finding {
		for i := range a.Findings {
			if f := &a.Findings[i]; f.Rule == "DARB-PATH-002" && f.Jewel == piiBucket && f.Entry == entry {
				return f
			}
		}
		return nil
	}
	base := byEntry(analyzeVariant(t, "08_rbac_create_pods/vulnerable", nil), ci)
	if base == nil || base.CutCost != 1 || !strings.HasPrefix(base.Chokepoints[0], "CAN_DECRYPT") {
		t.Fatalf("baseline: the role's decrypt is cut at cost 1: %+v", base)
	}
	a := analyzeVariant(t, "08_rbac_create_pods/vulnerable", func(dir string) {
		appendConfig(t, dir, "intended_access:", "  - principal: \"k8s:prod/payments/Deployment/api\"",
			"    action: \"s3:GetObject\"", "    resource: \""+piiBucket+"/*\"")
	})
	if f := findingFor(a, "DARB-PATH-001", piiBucket); f != nil {
		t.Fatalf("the declared pair is reported: %+v", f)
	}
	f := byEntry(a, ci)
	if f == nil || f.NoFix || len(f.Chokepoints) == 0 {
		t.Fatalf("ci-runner's path keeps a cut: %+v", f)
	}
	for _, c := range f.Chokepoints {
		if strings.HasPrefix(c, "CAN_DECRYPT") || strings.HasPrefix(c, "CAN_READ") || strings.HasPrefix(c, "ASSUMES") {
			t.Fatalf("ci-runner's cut takes an edge of the intended path: %v", f.Chokepoints)
		}
	}
}
