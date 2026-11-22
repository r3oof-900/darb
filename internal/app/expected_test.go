package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/rules"
)

// expected.json (DESIGN.md §8.2): written by hand before the rules existed.
// A mismatch is investigated and shown in review; the files are never
// edited to match the engine.

type expectedFile struct {
	Format         string             `json:"format"`
	DerivedFrom    string             `json:"derived_from"`
	ExitCode       *int               `json:"exit_code"`
	Collected      *int               `json:"collected"`
	ParseErrors    []string           `json:"parse_errors"`
	Distinct       bool               `json:"distinct_fingerprints"`
	Findings       []expectedFinding  `json:"findings"`
	Absent         []expectedFinding  `json:"absent"`
	IntendedAccess []expectedIntended `json:"intended_access"`
	NoEdges        []expectedNoEdge   `json:"no_edges"`
}

type expectedFinding struct {
	Rule     string  `json:"rule"`
	Entry    *string `json:"entry"`
	Jewel    string  `json:"jewel"`
	Resource string  `json:"resource"`
	// Fingerprint: computed in tests/fixtures/expected_source.py from the
	// documented formula (DESIGN.md 5, 8), not from the engine.
	Fingerprint string   `json:"fingerprint"`
	Path        []string `json:"path"`
	Confirmed   *bool    `json:"confirmed"`
	// Status (DESIGN.md 6.2) and, for a path with unknowns, texts each of
	// which some undecided entry must contain (the unknown's name, what
	// resolves it).
	Status      string   `json:"status"`
	Undecided   []string `json:"undecided"`
	Confidence  string   `json:"confidence"`
	Score       *int     `json:"score"`
	Severity    string   `json:"severity"`
	Chokepoints []string `json:"chokepoints"`
	Alternative []string `json:"alternative_fix"`
	Defaults    []string `json:"defaults_used"`
	// Fix: the side the cut chose for each chokepoint edge and its cost
	// (SCORING.md §4), compared where stated.
	Fix []expectedFix `json:"fix"`
	// OtherSide: the other sides of the cut edges; AlternativeDetail: the
	// cheapest fix of each alternative_fix edge.
	OtherSide         []expectedFix `json:"other_side_fix"`
	AlternativeDetail []expectedFix `json:"alternative_fix_detail"`
	// Phase 6 review: the findings of other rules the cut also fixes, the
	// underlying edges no change breaks, the remediation status and the
	// shared fixes, compared where stated.
	AlsoFixes         *[]rules.FindingRef `json:"also_fixes"`
	Uncuttable        *[]expectedEdge     `json:"uncuttable"`
	RemediationStatus string              `json:"remediation_status"`
	SharedFix         []string            `json:"shared_fix_possible"`
	WorstCasePath     []string            `json:"worst_case_path"`
	// Remediation: the strategies in output order, which are verified on
	// both levels, and the advice (DESIGN.md §9.2); or missing: an UNKNOWN
	// path gets what would decide it, no fix.
	Remediation *expectedRemediation `json:"remediation"`
}

type expectedRemediation struct {
	Order    []string `json:"order"`
	Verified []bool   `json:"verified"`
	Note     string   `json:"note"`
	Missing  bool     `json:"missing"`
}

type expectedFix struct {
	Edge string `json:"edge"`
	Side string `json:"side"`
	Kind string `json:"fix_kind"`
	Cost int64  `json:"cost"`
	// Policy: compared where stated (a detach names the managed policy, a
	// resolve step the unknown policy); Resolve: the deciding command.
	Policy  string `json:"policy,omitempty"`
	Resolve string `json:"resolve,omitempty"`
}

type expectedEdge struct {
	Edge string `json:"edge"`
}

// fixSteps keeps a step's policy only where the expected step states one.
func fixSteps(want []expectedFix, steps []rules.FixStep) []expectedFix {
	out := []expectedFix{}
	for i, s := range steps {
		x := expectedFix{Edge: s.Edge, Side: s.Side, Kind: s.Kind, Cost: s.Cost, Resolve: s.Resolve}
		if i < len(want) && want[i].Policy != "" {
			x.Policy = s.Policy
		}
		out = append(out, x)
	}
	return out
}

// expectedNoEdge: no edge of any kind from one node to the other.
type expectedNoEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type expectedIntended struct {
	Principal, Action, Resource, Status string
}

// kindOf maps a canonical identity to its node kind, for the independent
// fingerprint computation.
func kindOf(identity string) model.NodeKind {
	switch {
	case identity == "anonymous":
		return model.KindAnonymous
	case strings.HasPrefix(identity, "eks-nodegroup:"):
		return model.KindEKSNodeGroup
	case strings.Contains(identity, "//Namespace/"):
		return model.KindK8sNamespace
	case strings.HasPrefix(identity, "k8s:") && strings.Contains(identity, "/Secret/"):
		return model.KindK8sSecret
	case strings.HasPrefix(identity, "arn:aws:secretsmanager:"):
		return model.KindSecret
	case strings.HasPrefix(identity, "arn:aws:ssm:") && strings.Contains(identity, ":parameter/"):
		return model.KindSSMParameter
	case strings.HasPrefix(identity, "k8s:"):
		return model.KindK8sWorkload
	case strings.HasPrefix(identity, "arn:aws:s3:::"):
		return model.KindS3Bucket
	case strings.Contains(identity, ":role/"):
		return model.KindIAMRole
	}
	return model.KindKMSKey
}

// fingerprint is the §8 formula written again, independently of the engine:
// it names the problem (rule, entry, jewel or resource), never the fix.
func fingerprint(rule string, f *expectedFinding) string {
	parts := []string{"darb/fingerprint/v1", rule, "1"}
	if f.Resource != "" {
		parts = append(parts, string(model.NewID(kindOf(f.Resource), f.Resource)))
	} else {
		parts = append(parts, string(model.NewID(kindOf(*f.Entry), *f.Entry)), string(model.NewID(kindOf(f.Jewel), f.Jewel)))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, string(rune(0)))))
	return hex.EncodeToString(sum[:])
}

func matches(e *expectedFinding, a *rules.Finding) bool {
	if e.Rule != a.Rule {
		return false
	}
	if e.Resource != "" {
		return e.Resource == a.Resource
	}
	return e.Jewel == a.Jewel && (e.Entry == nil || *e.Entry == a.Entry)
}

func compareFinding(e *expectedFinding, a *rules.Finding) []string {
	var diffs []string
	diff := func(field string, want, got any) {
		w, _ := json.Marshal(want)
		g, _ := json.Marshal(got)
		if !bytes.Equal(w, g) {
			diffs = append(diffs, fmt.Sprintf("%s: want %s, got %s", field, w, g))
		}
	}
	if e.Path != nil {
		diff("path", e.Path, a.Path)
	}
	if e.Confirmed != nil {
		diff("confirmed", *e.Confirmed, a.Confirmed)
	}
	if e.Confidence != "" {
		diff("confidence", e.Confidence, a.Confidence)
	}
	if e.Status != "" {
		diff("status", e.Status, a.Status)
	}
	for _, want := range e.Undecided {
		if !slices.ContainsFunc(a.Undecided, func(u string) bool { return strings.Contains(u, want) }) {
			diffs = append(diffs, fmt.Sprintf("undecided: no entry names %q (got %q)", want, a.Undecided))
		}
	}
	if e.Score != nil {
		diff("score", *e.Score, a.Factors.Score)
		diff("severity", e.Severity, a.Factors.Severity)
	}
	if e.Chokepoints != nil {
		diff("chokepoints", e.Chokepoints, nonEmpty(a.Chokepoints))
		diff("alternative_fix", e.Alternative, nonEmpty(a.Alternative))
	}
	if e.Defaults != nil {
		diff("defaults_used", e.Defaults, a.DefaultsUsed)
	}
	// Every expected cut states its fixes (Phase 5, step 1): a cost or kind
	// that changes unnoticed is a difference.
	if len(e.Chokepoints) > 0 && (e.Fix == nil || e.OtherSide == nil || e.AlternativeDetail == nil) {
		diffs = append(diffs, "the expected file states a cut without fix, other_side_fix and alternative_fix_detail")
	}
	if e.Fix != nil {
		diff("fix", e.Fix, fixSteps(e.Fix, a.Fix))
	}
	if e.OtherSide != nil {
		diff("other_side_fix", e.OtherSide, fixSteps(e.OtherSide, a.OtherSideFix))
	}
	if e.AlternativeDetail != nil {
		diff("alternative_fix_detail", e.AlternativeDetail, fixSteps(e.AlternativeDetail, a.AlternativeDetail))
	}
	diffs = append(diffs, comparePhase6(e, a)...)
	if e.Entry != nil || e.Resource != "" {
		diff("fingerprint (independent §8 formula)", fingerprint(e.Rule, e), a.Fingerprint)
		diff("fingerprint (expected_source.py)", e.Fingerprint, a.Fingerprint)
	}
	return diffs
}

func nonEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func describe(e *expectedFinding) string {
	if e.Resource != "" {
		return e.Rule + " " + e.Resource
	}
	entry := "<any entry>"
	if e.Entry != nil {
		entry = *e.Entry
	}
	return e.Rule + " " + entry + " -> " + e.Jewel
}

// compareExpected returns every difference between a variant's expected
// file and the engine's analysis.
func compareExpected(t *testing.T, exp *expectedFile, a *Analysis) []string {
	t.Helper()
	var out []string
	used := map[int]bool{}
	for i := range exp.Findings {
		e := &exp.Findings[i]
		found := -1
		for j := range a.Findings {
			if !used[j] && matches(e, &a.Findings[j]) {
				found = j
				break
			}
		}
		if found < 0 {
			out = append(out, "missing finding: "+describe(e))
			continue
		}
		used[found] = true
		for _, d := range compareFinding(e, &a.Findings[found]) {
			out = append(out, describe(e)+": "+d)
		}
	}
	for j := range a.Findings {
		if !used[j] {
			f := &a.Findings[j]
			out = append(out, fmt.Sprintf("extra finding: %s %s%s -> %s (score %d %s, path %v)", f.Rule, f.Resource, f.Entry, f.Jewel, f.Factors.Score, f.Factors.Severity, f.Path))
		}
	}
	for i := range exp.Absent {
		for j := range a.Findings {
			if matches(&exp.Absent[i], &a.Findings[j]) {
				out = append(out, "must be absent: "+describe(&exp.Absent[i]))
			}
		}
	}
	for _, ia := range exp.IntendedAccess {
		status := "missing"
		for _, r := range a.IntendedAccess {
			if r.Principal == ia.Principal && r.Resource == ia.Resource && r.Action == ia.Action {
				status = r.Status
			}
		}
		if status != ia.Status {
			out = append(out, fmt.Sprintf("intended access %s %s %s: want %s, got %s", ia.Principal, ia.Action, ia.Resource, ia.Status, status))
		}
	}
	out = append(out, noEdges(exp.NoEdges, a.AccessGraph)...)
	if exp.ExitCode != nil && *exp.ExitCode != a.ExitCode {
		out = append(out, fmt.Sprintf("exit code: want %d, got %d", *exp.ExitCode, a.ExitCode))
	}
	if exp.Collected != nil && *exp.Collected != a.Collected {
		out = append(out, fmt.Sprintf("collected: want %d, got %d", *exp.Collected, a.Collected))
	}
	for _, f := range exp.ParseErrors {
		ok := false
		for i := range a.Gaps {
			ok = ok || (string(a.Gaps[i].Kind) == "parse-error" && strings.HasSuffix(filepath.ToSlash(a.Gaps[i].File), f) && a.Gaps[i].Line > 0)
		}
		if !ok {
			out = append(out, "parse error with a line not reported for "+f)
		}
	}
	if exp.Distinct {
		seen := map[string]bool{}
		for i := range a.Findings {
			if seen[a.Findings[i].Fingerprint] {
				out = append(out, "fingerprints are not distinct")
			}
			seen[a.Findings[i].Fingerprint] = true
		}
	}
	return out
}

func TestExpectedFindings(t *testing.T) {
	variants, err := filepath.Glob(filepath.Join(repoRoot(t), "tests", "fixtures", "*", "*", "expected*.json"))
	if err != nil || len(variants) < 36 {
		t.Fatalf("expected.json files: %d (%v)", len(variants), err)
	}
	var report []string
	for _, file := range variants {
		variant := filepath.Dir(file)
		name := filepath.Base(filepath.Dir(variant)) + "/" + filepath.Base(variant)
		golden := "normalized.golden.json"
		if filepath.Base(file) == "expected.static.json" {
			golden, name = "normalized.static.golden.json", name+" (static)"
		}
		data, err := os.ReadFile(file) //nolint:gosec // G304: fixture path from the repository.
		if err != nil {
			t.Fatal(err)
		}
		var exp expectedFile
		if jerr := json.Unmarshal(data, &exp); jerr != nil || exp.Format != "darb-expected/v1" {
			t.Fatalf("%s: %v", file, jerr)
		}
		dir := copyTree(t, variant)
		in := scansFor(t, dir)[golden]
		l, err := Load(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(l, in.Config, DefaultFailOn)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range compareExpected(t, &exp, a) {
			report = append(report, name+": "+d)
		}
		for i := range exp.Findings {
			e := &exp.Findings[i]
			if e.Remediation == nil {
				continue
			}
			for j := range a.Findings {
				if matches(e, &a.Findings[j]) {
					for _, d := range compareRemediation(t, in, l, a, e, &a.Findings[j]) {
						report = append(report, name+": "+describe(e)+": "+d)
					}
				}
			}
		}
	}
	compareWithOpen(t, report)
}

// The no_edges check finds an edge that exists (the account's own read).
func TestNoEdgesDetects(t *testing.T) {
	a := analyzeVariant(t, "14_same_names_two_accounts/vulnerable", nil)
	own := []expectedNoEdge{{From: "arn:aws:iam::111122223333:role/app", To: "arn:aws:s3:::data-111122223333"}}
	if got := noEdges(own, a.AccessGraph); len(got) == 0 {
		t.Fatal("an existing edge must be reported")
	}
}
