package app

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/r3oof-900/darb/internal/access"
	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/eval/condition"
	"github.com/r3oof-900/darb/internal/eval/match"
	"github.com/r3oof-900/darb/internal/model"
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

// TestPodIdentityThroughEvaluator: scenario 17 is scenario 1 through EKS Pod
// Identity. The association links payments/api to the role; the trust policy
// is decided by the evaluator for sts:AssumeRole and sts:TagSession with the
// session tags EKS adds; the role's own policy then reads (or not) the PII.
func TestPodIdentityThroughEvaluator(t *testing.T) {
	for _, c := range []struct {
		variant string
		readPII eval.Verdict
	}{
		{"vulnerable", eval.Allow},
		{"fixed", eval.ImplicitDeny},
	} {
		t.Run(c.variant, func(t *testing.T) {
			dir := copyTree(t, filepath.Join(repoRoot(t), "tests", "fixtures", "17_pod_identity_classic", c.variant))
			l, err := Load(context.Background(), scansFor(t, dir)["normalized.golden.json"])
			if err != nil {
				t.Fatal(err)
			}
			inv := l.Inventory
			const role = "arn:aws:iam::111122223333:role/payments-api"
			trust := trustOf(t, inv, role)
			cluster := clusterNamed(t, inv, "prod")
			agent := access.AgentInstalled(inv, cluster.Key())
			if agent != model.True {
				t.Fatalf("the agent add-on is in the input: %s", agent)
			}
			api := saNamed(inv, "payments", "api")
			if api.RoleARN != "" {
				t.Fatalf("no IRSA annotation in this scenario: %q", api.RoleARN)
			}
			assoc := access.AssociationsFor(inv, api)
			if len(assoc) != 1 || assoc[0].RoleARN != role {
				t.Fatalf("associations of payments/api: %+v", assoc)
			}
			if got := access.PodIdentityAssume(assoc[0], cluster, trust, "111122223333", agent); got.Verdict != eval.Allow ||
				got.AssumeRole != eval.Allow || got.TagSession != eval.Allow {
				t.Errorf("payments/api assumes the role: %+v", got)
			}
			// The same role associated with another service account: the
			// trust policy's tag conditions refuse it.
			other := *assoc[0]
			other.Namespace, other.ServiceAccount = "tools", "default"
			if got := access.PodIdentityAssume(&other, cluster, trust, "111122223333", agent); got.Verdict != eval.ImplicitDeny {
				t.Errorf("tools/default: %+v", got)
			}
			if got := access.AssociationsFor(inv, saNamed(inv, "tools", "default")); len(got) != 0 {
				t.Errorf("tools/default has no association: %+v", got)
			}
			// What the session can do with the role's identity policy: scenario 1.
			bucket := "arn:aws:s3:::acme-customer-pii"
			ps := &eval.PolicySet{}
			for _, p := range inv.Policies {
				if p.Target == model.NewID(model.KindIAMRole, role) {
					ps.Identity = append(ps.Identity, p.Doc)
				}
			}
			req := &eval.Request{
				Principal: match.RequestPrincipal{
					Kind: match.KindAssumedRole, ARN: "arn:aws:sts::111122223333:assumed-role/payments-api/eks-prod-api",
					Account: "111122223333", SourceARN: role,
				},
				Action: "s3:GetObject", Resource: bucket + "/customers.csv", ResourceAccount: "111122223333",
				Context: condition.NewContext(&condition.Input{Default: condition.StateAbsent}),
			}
			if got := eval.Evaluate(req, ps); got.Verdict != c.readPII {
				t.Errorf("read PII: %s, want %s", got.Verdict, c.readPII)
			}
		})
	}
}
