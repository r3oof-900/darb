package app

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/rules"
)

// EXPOSED_TO (SCORING.md §4.1): without assume-compromised the attacker
// comes from the internet, whose EXPOSED_TO edge to the public load balancer's
// workload is cuttable at 20. The score is the same as with the workload as
// its own exposed entry (the exposure is the factor, not a hop).
func TestExposedToIsCuttable(t *testing.T) {
	const entry = "internet"
	noCompromise := func(dir string) {
		appendConfig(t, dir, "threat_model:", "  assume_compromised: false")
	}
	a := analyzeVariant(t, "01_classic/vulnerable", noCompromise)
	f := findingFor(a, "DARB-PATH-001", piiBucket)
	if f == nil || f.Entry != entry || f.Factors.Score != 729 || len(f.Path) == 0 || !strings.HasPrefix(f.Path[0], "EXPOSED_TO ") {
		t.Fatalf("internet entry, same score: %+v", f)
	}
	if len(f.Fix) != 1 || !strings.HasPrefix(f.Fix[0].Edge, "CAN_DECRYPT") || f.CutCost != 1 {
		t.Fatalf("the cheap decrypt is still the cut: %+v", f.Fix)
	}

	// The read declared intended: every IAM edge on its paths is uncuttable,
	// so the only cut left is the exposure.
	a = analyzeVariant(t, "01_classic/vulnerable", func(dir string) {
		noCompromise(dir)
		appendConfig(t, dir, "intended_access:", "  - principal: \"k8s:prod/payments/Deployment/api\"",
			"    action: \"s3:GetObject\"", "    resource: \""+piiBucket+"/*\"")
	})
	f = findingFor(a, "DARB-PATH-001", piiBucket)
	if f == nil || f.NoFix || len(f.Fix) != 1 || !strings.HasPrefix(f.Fix[0].Edge, "EXPOSED_TO ") ||
		f.Fix[0].Side != graph.SideExposure || f.Fix[0].Kind != graph.FixRevoke || f.CutCost != 20 {
		t.Fatalf("the exposure is the cut, revoke, 20: %+v", f)
	}

	// With assume-compromised (the default) the pod is the entry, and the
	// pair is the declared access itself: not reported, whatever the
	// jewel's classification (decided after v0.1.0-rc.1; it was a finding
	// with no fix).
	a = analyzeVariant(t, "01_classic/vulnerable", func(dir string) {
		appendConfig(t, dir, "intended_access:", "  - principal: \"k8s:prod/payments/Deployment/api\"",
			"    action: \"s3:GetObject\"", "    resource: \""+piiBucket+"/*\"")
	})
	if f = findingFor(a, "DARB-PATH-001", piiBucket); f != nil {
		t.Fatalf("assume-compromised: the declared pair is reported: %+v", f)
	}
}

// DARB-POST-008 is graded by reachability: analytics-admin's
// AdministratorAccess is high while payments-api can assume it (06
// vulnerable) and medium once nothing reaches it (06 fixed); the evidence
// names the entries (reachable_from).
func TestBroadGrantByReachability(t *testing.T) {
	const admin = "arn:aws:iam::444455556666:role/analytics-admin"
	find := func(a *Analysis) (sev string, evidence []string) {
		for i := range a.Findings {
			if f := &a.Findings[i]; f.Rule == "DARB-POST-008" && f.Resource == admin {
				return f.Factors.Severity, f.Evidence
			}
		}
		t.Fatal("no DARB-POST-008 for analytics-admin")
		return "", nil
	}
	sev, ev := find(analyzeVariant(t, "06_role_chain_cross_account/vulnerable", nil))
	if sev != "high" || !slices.Contains(ev, "reachable_from: [k8s:arn:aws:eks:us-east-1:111122223333:cluster/prod/payments/Deployment/api]") {
		t.Errorf("reached: %s %v", sev, ev)
	}
	sev, ev = find(analyzeVariant(t, "06_role_chain_cross_account/fixed", nil))
	if sev != "medium" || !slices.Contains(ev, "reachable_from: none") {
		t.Errorf("not reached: %s %v", sev, ev)
	}
}

// DARB-POST-001 1.0.1: a wildcard scoped to one namespace accepts every
// new service account there. Found by the comparison with the previous
// tool's samples (system:serviceaccount:fraud-analytics:*).
func TestTrustWildcardInOneNamespace(t *testing.T) {
	a := analyzeVariant(t, "01_classic/vulnerable", func(dir string) {
		file := filepath.Join(dir, "terraform", "trust_pinned.tf")
		replaceIn(t, file, `test     = "StringEquals"
      variable = "${local.oidc_host}:sub"`, `test     = "StringLike"
      variable = "${local.oidc_host}:sub"`)
		replaceIn(t, file, `"system:serviceaccount:payments:api"`, `"system:serviceaccount:payments:*"`)
	})
	var f *rules.Finding
	for i := range a.Findings {
		if a.Findings[i].Rule == "DARB-POST-001" {
			f = &a.Findings[i]
		}
	}
	if f == nil || !slices.ContainsFunc(f.Evidence, func(e string) bool { return strings.HasSuffix(e, "allows system:serviceaccount:payments:darb-probe") }) {
		t.Fatalf("a namespace-scoped wildcard trust must be reported: %+v", f)
	}
}

// An unconfirmed path says why: what would decide it (scenario 10: the
// organization ID the key policy conditions on).
func TestUnconfirmedPathSaysWhy(t *testing.T) {
	f := findingFor(analyzeVariant(t, "10_kms_principal_org_id/vulnerable", nil), "DARB-PATH-001", piiBucket)
	if f == nil || f.Confirmed || len(f.Undecided) != 1 || !strings.Contains(f.Undecided[0], `assume: {"aws:PrincipalOrgID"`) {
		t.Fatalf("undecided: %+v", f)
	}
	if g := findingFor(analyzeVariant(t, "01_classic/vulnerable", nil), "DARB-PATH-001", piiBucket); len(g.Undecided) != 0 {
		t.Fatalf("a confirmed path has nothing undecided: %v", g.Undecided)
	}
}
