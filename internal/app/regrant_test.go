package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/graph"
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
	for _, f := range e.Fixes {
		if f.Side == side {
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
	f := findingFor(a, "CLAPA-PATH-001", piiBucket)
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
	f = findingFor(a, "CLAPA-PATH-001", piiBucket)
	if f == nil || len(f.Chokepoints) != 1 || f.Chokepoints[0] != "ASSUMES k8s:prod/payments/ServiceAccount/api -> "+apiRole {
		t.Fatalf("PutBucketPolicy + CreateGrant: the cut must be the hop into the role: %+v", f)
	}
}

// Scenario 6: analytics-admin can rewrite its own policies, the warehouse
// key's policy and the bucket's. With the hop into it declared uncuttable,
// no edge from it (or from its any-permission twin) may be in the cut.
func TestNoCutAfterSelfModifyingRole(t *testing.T) {
	const admin = "arn:aws:iam::444455556666:role/analytics-admin"
	a := analyzeVariant(t, "06_role_chain_cross_account/vulnerable", func(dir string) {
		file := filepath.Join(dir, "clapa.yaml")
		data, err := os.ReadFile(file) //nolint:gosec // G304: inside the test's temp copy.
		if err != nil {
			t.Fatal(err)
		}
		extra := strings.Join([]string{
			"remediation:", "  uncuttable_edges:",
			"    - {kind: ASSUMES, from: \"" + apiRole + "\", to: \"" + admin + "\", reason: test}", "",
		}, string(rune(10)))
		if err := os.WriteFile(file, append(data, extra...), 0o600); err != nil { //nolint:gosec // G703: temp copy.
			t.Fatal(err)
		}
	})
	f := findingFor(a, "CLAPA-PATH-001", "arn:aws:s3:::acme-analytics-warehouse")
	if f == nil || len(f.Chokepoints) == 0 {
		t.Fatalf("a cut before the admin role must exist: %+v", f)
	}
	for _, c := range f.Chokepoints {
		if strings.Contains(c, admin+" ->") || strings.Contains(c, admin+" (any permission) ->") {
			t.Errorf("cut after the self-modifying role: %s", c)
		}
	}
	for _, s := range f.Fix {
		if strings.Contains(s.Edge, admin+" ->") {
			t.Errorf("identity-side fix after the self-modifying role: %+v", s)
		}
	}
}
