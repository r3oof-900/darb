package app

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/r3oof-900/clapa/internal/access"
	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/model"
)

// TestIRSATrustThroughEvaluator: scenarios 4 and 5 are decided by the
// evaluator on the trust policy as normalized from Terraform, with the
// context keys the IRSA request carries (<issuer>:sub from the service
// account, <issuer>:aud) — not by separate trust logic.
func TestIRSATrustThroughEvaluator(t *testing.T) {
	cases := []struct {
		fixture       string
		api, otherSA  eval.Verdict // payments/api, tools/default
		withoutIssuer eval.Verdict // payments/api when the cluster issuer is not configured
	}{
		{"01_classic/vulnerable", eval.Allow, eval.ImplicitDeny, eval.Unknown},
		{"04_wildcard_sub/vulnerable", eval.Allow, eval.Allow, eval.Unknown},
		{"04_wildcard_sub/fixed", eval.Allow, eval.ImplicitDeny, eval.Unknown},
		{"05_aud_only/vulnerable", eval.Allow, eval.Allow, eval.Unknown},
		{"05_aud_only/fixed", eval.Allow, eval.ImplicitDeny, eval.Unknown},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			dir := copyTree(t, filepath.Join(repoRoot(t), "tests", "fixtures", filepath.FromSlash(c.fixture)))
			l, err := Load(context.Background(), scansFor(t, dir)["normalized.golden.json"])
			if err != nil {
				t.Fatal(err)
			}
			inv := l.Inventory
			trust := trustOf(t, inv, "arn:aws:iam::111122223333:role/payments-api")
			cluster := clusterNamed(t, inv, "prod")
			check := func(sa *model.ServiceAccount, cl *model.Cluster, want eval.Verdict) {
				t.Helper()
				req := access.IRSARequest(sa, cl, "arn:aws:iam::111122223333:role/payments-api", "111122223333", "aws")
				if got := eval.Evaluate(req, access.TrustPolicySet(trust)); got.Verdict != want {
					t.Errorf("%s: %s, want %s (%+v)", sa.SubjectString(), got.Verdict, want, got)
				}
			}
			check(saNamed(inv, "payments", "api"), cluster, c.api)
			other := &model.ServiceAccount{Cluster: "prod", Namespace: "tools", Name: "default", Audience: "sts.amazonaws.com"}
			check(other, cluster, c.otherSA)
			noIssuer := *cluster
			noIssuer.OIDCIssuer = ""
			check(saNamed(inv, "payments", "api"), &noIssuer, c.withoutIssuer)
		})
	}
}

func trustOf(t *testing.T, inv *model.Inventory, roleARN string) *model.PolicyDocument {
	t.Helper()
	id := model.NewID(model.KindIAMRole, roleARN)
	for _, tr := range inv.Trusts {
		if tr.Role() == id {
			return tr.Policy()
		}
	}
	t.Fatalf("no trust policy for %s", roleARN)
	return nil
}

func clusterNamed(t *testing.T, inv *model.Inventory, name string) *model.Cluster {
	t.Helper()
	for _, c := range inv.Clusters {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cluster %s not found", name)
	return nil
}

func saNamed(inv *model.Inventory, ns, name string) *model.ServiceAccount {
	for _, sa := range inv.ServiceAccounts {
		if sa.Namespace == ns && sa.Name == name {
			return sa
		}
	}
	return &model.ServiceAccount{Cluster: "prod", Namespace: ns, Name: name, Audience: "sts.amazonaws.com"}
}
