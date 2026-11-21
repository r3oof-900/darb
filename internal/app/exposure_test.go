package app

import (
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/graph"
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
	f := findingFor(a, "CLAPA-PATH-001", piiBucket)
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
	f = findingFor(a, "CLAPA-PATH-001", piiBucket)
	if f == nil || f.NoFix || len(f.Fix) != 1 || !strings.HasPrefix(f.Fix[0].Edge, "EXPOSED_TO ") ||
		f.Fix[0].Side != graph.SideExposure || f.Fix[0].Kind != graph.FixRevoke || f.CutCost != 20 {
		t.Fatalf("the exposure is the cut, revoke, 20: %+v", f)
	}

	// With assume-compromised (the default) the pod is the entry: the
	// exposure is never on a path, so intended access leaves no fix.
	a = analyzeVariant(t, "01_classic/vulnerable", func(dir string) {
		appendConfig(t, dir, "intended_access:", "  - principal: \"k8s:prod/payments/Deployment/api\"",
			"    action: \"s3:GetObject\"", "    resource: \""+piiBucket+"/*\"")
	})
	if f = findingFor(a, "CLAPA-PATH-001", piiBucket); f == nil || !f.NoFix {
		t.Fatalf("assume-compromised: no fix: %+v", f)
	}
}
