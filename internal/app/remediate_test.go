package app

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/remediate"
	"github.com/r3oof-900/clapa/internal/rules"
)

// Phase 5 (DESIGN.md §9): every fix is verified in memory and on files.

var (
	lf   = string(rune(10))
	crlf = string([]byte{13, 10})
)

// scanFixture scans a copy of a fixture variant, optionally edited first.
func scanFixture(t *testing.T, fixture string, edit func(dir string)) (*Inputs, *Loaded, *Analysis) {
	t.Helper()
	dir := copyTree(t, filepath.Join(repoRoot(t), "tests", "fixtures", filepath.FromSlash(fixture)))
	if edit != nil {
		edit(dir)
	}
	in := scansFor(t, dir)["normalized.golden.json"]
	l, err := Load(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Analyze(l, in.Config, DefaultFailOn)
	if err != nil {
		t.Fatal(err)
	}
	return in, l, a
}

func writeFile(t *testing.T, file, content string) {
	t.Helper()
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, file string) string {
	t.Helper()
	data, err := os.ReadFile(file) //nolint:gosec // G304: inside the test's temp copy.
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

var arnInFix = regexp.MustCompile(`arn:[a-z0-9-]+:[^"\s,\]}]*`)

// noInventedNames: every ARN a fix writes is one of the input (DESIGN.md
// §9.3), or an object pattern of an input bucket.
func noInventedNames(t *testing.T, inv *model.Inventory, r *Remediation) {
	t.Helper()
	known := map[string]bool{}
	for _, p := range inv.Principals {
		known[p.Identity()] = true
	}
	for _, res := range inv.Resources {
		known[res.ARN()] = true
	}
	var added []string
	for _, line := range strings.Split(r.Patch.Diff(), lf) {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			added = append(added, line)
		}
	}
	for _, p := range r.Patch.Policies {
		added = append(added, p.Document)
	}
	for _, text := range added {
		for _, arn := range arnInFix.FindAllString(text, -1) {
			base, _, _ := strings.Cut(arn, "/*")
			if !known[arn] && !known[base] && !known[strings.TrimSuffix(arn, "/*")] {
				t.Errorf("a fix writes %s, which is not in the input", arn)
			}
		}
	}
}

// The definition of done (DESIGN.md §12, Phase 5): for every vulnerable
// scenario, the patch applied to a copy and rescanned no longer reports the
// finding. Two scenarios are not patched, on purpose: 10 is UNKNOWN (what
// would decide it is reported instead) and 13's grant comes from a module
// input the input cannot choose a value for (a TODO naming that input).
func TestEveryVulnerableScenarioIsFixed(t *testing.T) {
	variants, err := filepath.Glob(filepath.Join(repoRoot(t), "tests", "fixtures", "*", "vulnerable", "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	fixed := 0
	for _, file := range variants {
		name := filepath.Base(filepath.Dir(filepath.Dir(file)))
		in, l, a := scanFixture(t, name+"/vulnerable", nil)
		for i := range a.Findings {
			f := &a.Findings[i]
			if f.Kind != rules.KindPath {
				continue
			}
			r, err := Remediate(t.Context(), in, l, a, f.Fingerprint)
			if err != nil {
				t.Fatalf("%s %s: %v", name, f.Entry, err)
			}
			switch name {
			case "10_kms_principal_org_id":
				if f.Confirmed || len(r.Plan.Missing) == 0 || r.Patch != nil {
					t.Errorf("%s: an UNKNOWN path gets what is missing, no patch: %+v", name, r.Plan)
				}
			case "22_direct_and_escalation":
				// Phase 6 review: the direct path rests on an unresolved variable
				// (a resolve step, SCORING.md 4.1): no patch until it is decided.
				// The escalation (confirmed) is fixed like any other.
				if !f.Confirmed {
					if r.Patch != nil || len(r.Plan.Pending) == 0 {
						t.Errorf("%s: an unconfirmed path gets its resolve steps, no patch: %+v", name, r.Plan)
					}
					break
				}
				if !r.Accepted() {
					t.Errorf("%s %s: not accepted: memory %v, files %v", name, f.Rule, r.Memory.Reasons, r.Files.Reasons)
					break
				}
				fixed++
			case "13_module_for_each":
				if !r.Memory.OK || r.Patch == nil || r.Patch.Complete() ||
					!strings.Contains(r.Patch.TODO[0], `input "bucket" of module "readers" at terraform/main.tf:4`) {
					t.Errorf("%s: a TODO naming the module input: %+v %+v", name, r.Memory, r.Patch)
				}
			default:
				if !r.Accepted() {
					t.Errorf("%s %s: not accepted: memory %v, files %v", name, f.Entry, r.Memory.Reasons, r.Files.Reasons)
					continue
				}
				if _, still := r.Files.After.Findings[f.Fingerprint]; still {
					t.Errorf("%s %s: still reported after the patch", name, f.Entry)
				}
				noInventedNames(t, l.Inventory, r)
				fixed++
			}
		}
	}
	// 01, 01b, 04 (2), 04b, 05 (2), 06, 07, 08 (2), 09, 12, 14 (2), 16, 17, 18 (2), 19, 20, 21, 22 (PATH-002),
	// 23 (2: the mount, removed from the pod spec; the pod creation, by the token mount).
	if fixed != 25 {
		t.Fatalf("%d findings fixed, want 25", fixed)
	}
}

// Scenario 9 (hostNetwork + IMDS): a hostNetwork pod shares the node's
// network namespace, so IMDSv2 with a hop limit of 1 does not cut it off:
// the verifier rejects that fix. For a pod without hostNetwork it is the
// fix, and the verifier accepts it.
func TestScenario9HopLimit(t *testing.T) {
	const exports = "arn:aws:s3:::acme-customer-exports"
	hopLimit := func(l *Loaded, f *rules.Finding) *remediate.Plan {
		return &remediate.Plan{Fingerprint: f.Fingerprint, Changes: []remediate.Change{{
			Edge: "NODE_ROLE", Side: graph.SideNode, Kind: graph.FixNarrow,
			Edits: []remediate.Edit{{Op: remediate.OpNodeMetadata, NodeGroup: l.Inventory.NodeGroups[0], Tokens: "required", HopLimit: 1}},
		}}}
	}
	in, l, a := scanFixture(t, "09_hostnetwork_imds/vulnerable", nil)
	f := findingFor(a, "CLAPA-PATH-001", exports)
	r, err := verifyPlan(t.Context(), in, l, a, hopLimit(l, f))
	if err != nil {
		t.Fatal(err)
	}
	if r.Memory.OK || !slices.ContainsFunc(r.Memory.Reasons, func(s string) bool { return strings.Contains(s, "is still reported") }) {
		t.Fatalf("hostNetwork: the hop limit must be rejected: %+v", r.Memory)
	}
	// The fixes the access builder offers for the hostNetwork pod: the
	// metadata endpoint off (accepted); removing hostNetwork is not one,
	// since this node lets every pod reach IMDS (IMDSv1, hop limit 2).
	node := nodeRoleEdge(t, a, f)
	if len(node.Fixes) != 1 || node.Fixes[0].Policy != "node group default: http_endpoint = disabled" {
		t.Fatalf("hostNetwork fixes: %+v", node.Fixes)
	}

	// Without hostNetwork the hop limit is the node-side fix, and it holds.
	in, l, a = scanFixture(t, "09_hostnetwork_imds/vulnerable", func(dir string) {
		replaceIn(t, filepath.Join(dir, "k8s", "monitor.yaml"), "      hostNetwork: true"+lf, "")
	})
	f = findingFor(a, "CLAPA-PATH-001", exports)
	if f == nil {
		t.Fatal("without hostNetwork the pod still reaches IMDS (IMDSv1, hop limit 2)")
	}
	if node = nodeRoleEdge(t, a, f); len(node.Fixes) != 1 || node.Fixes[0].Kind != graph.FixNarrow || node.Fixes[0].Cost != 3 {
		t.Fatalf("pod network fixes: %+v", node.Fixes)
	}
	r, err = verifyPlan(t.Context(), in, l, a, hopLimit(l, f))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Accepted() {
		t.Fatalf("without hostNetwork the hop limit must be accepted: %v %v", r.Memory.Reasons, r.Files.Reasons)
	}
	diff := r.Patch.Diff()
	if !strings.Contains(diff, `+    http_tokens                 = "required"`) || !strings.Contains(diff, "+    http_put_response_hop_limit = 1") {
		t.Fatalf("the launch template's metadata_options: %s", diff)
	}
}

func nodeRoleEdge(t *testing.T, a *Analysis, f *rules.Finding) *graph.Edge {
	t.Helper()
	for _, id := range f.PathEdges {
		if e := a.AccessGraph.Edge(id); e.Kind == graph.NodeRole {
			return e
		}
	}
	t.Fatal("no NODE_ROLE edge on the path")
	return nil
}

// Scenario 10 is UNKNOWN until the organization ID is known: no patch, the
// key to set. With it set (and matching), the path is decided, and the fix
// narrows the key policy's Principal "*" grant: a Deny for the role.
func TestScenario10Decided(t *testing.T) {
	in, l, a := scanFixture(t, "10_kms_principal_org_id/vulnerable", nil)
	f := findingFor(a, "CLAPA-PATH-001", piiBucket)
	r, err := Remediate(t.Context(), in, l, a, f.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if r.Patch != nil || len(r.Plan.Missing) != 1 || !strings.Contains(r.Plan.Missing[0], "aws:PrincipalOrgID") {
		t.Fatalf("UNKNOWN: what is missing: %+v", r.Plan)
	}
	in, l, a = scanFixture(t, "10_kms_principal_org_id/vulnerable", func(dir string) {
		appendConfig(t, dir, "assume:", `  "aws:PrincipalOrgID": ["o-a1b2c3d4e5"]`)
	})
	f = findingFor(a, "CLAPA-PATH-001", piiBucket)
	if f == nil || !f.Confirmed || f.Fix[0].Side != graph.SideResource || f.Fix[0].Kind != graph.FixNarrow {
		t.Fatalf("decided: %+v", f)
	}
	r, err = Remediate(t.Context(), in, l, a, f.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Accepted() || !strings.Contains(r.Patch.Diff(), "Principal = { AWS = [aws_iam_role.payments_api.arn] }") {
		t.Fatalf("the key policy deny: %v %v%s%s", r.Memory.Reasons, r.Files.Reasons, lf, r.Patch.Diff())
	}
}

// EXPOSED_TO: without assume-compromised and with the read intended, the
// cut is the exposure; its fix makes the Service ClusterIP.
func TestExposureRemediation(t *testing.T) {
	in, l, a := scanFixture(t, "01_classic/vulnerable", func(dir string) {
		appendConfig(t, dir, "threat_model:", "  assume_compromised: false", "intended_access:",
			`  - principal: "k8s:prod/payments/Deployment/api"`, `    action: "s3:GetObject"`, `    resource: "`+piiBucket+`/*"`)
	})
	f := findingFor(a, "CLAPA-PATH-001", piiBucket)
	r, err := Remediate(t.Context(), in, l, a, f.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Accepted() || !strings.Contains(r.Patch.Diff(), "+  type: ClusterIP") {
		t.Fatalf("the exposure removed: %v %v %+v", r.Memory.Reasons, r.Files.Reasons, r.Patch)
	}
}

// The two strategies on the files (Phase 5 review): after the mitigation
// the broad grant is still a finding (the scan is not clean: exit 1); after
// the verified root-cause fix of 1b it is gone and the scan is clean.
func TestMitigationLeavesTheBroadGrant(t *testing.T) {
	broad := func(a *Analysis) string {
		for i := range a.Findings {
			if a.Findings[i].Rule == "CLAPA-POST-008" && a.Findings[i].Resource == apiRole {
				return a.Findings[i].Fingerprint
			}
		}
		t.Fatal("no CLAPA-POST-008 for the role")
		return ""
	}
	in, l, a := scanFixture(t, "01_classic/vulnerable", nil)
	r, err := Remediate(t.Context(), in, l, a, findingFor(a, "CLAPA-PATH-001", piiBucket).Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if r.Plan.Strategy != remediate.StrategyMitigation || !r.Accepted() || r.Note == "" ||
		len(r.Others) != 1 || r.Others[0].Plan.Suggestion == "" || r.Others[0].Accepted() {
		t.Fatalf("1: mitigation first, the root cause an unverified suggestion: %+v", r.Plan)
	}
	if _, still := r.Files.After.Findings[broad(a)]; !still || r.Files.After.ExitCode != 1 {
		t.Fatalf("1: after the mitigation the broad grant stays reported (exit 1): %+v", r.Files.After)
	}

	in, l, a = scanFixture(t, "01b_classic_intended/vulnerable", nil)
	r, err = Remediate(t.Context(), in, l, a, findingFor(a, "CLAPA-PATH-001", piiBucket).Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if r.Plan.Strategy != remediate.StrategyRootCause || !r.Accepted() || r.Note != "" || len(r.Others) != 1 || !r.Others[0].Accepted() {
		t.Fatalf("1b: a verified root cause first, then the mitigation: %+v", r.Plan)
	}
	if _, still := r.Files.After.Findings[broad(a)]; still || r.Files.After.ExitCode != 0 {
		t.Fatalf("1b: after the root-cause fix the broad grant is gone and the scan is clean: %+v", r.Files.After)
	}
	if !strings.Contains(r.Patch.Diff(), "+      { Sid = \"DecryptAnything\", Effect = \"Allow\", Action = [\"kms:Decrypt\"], Resource = [aws_kms_key.receipts.arn] },") {
		t.Fatalf("1b: the Allow itself narrowed: %s", r.Patch.Diff())
	}
}
