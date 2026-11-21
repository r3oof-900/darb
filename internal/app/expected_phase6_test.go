package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/rules"
)

// comparePhase6: the fields the Phase 6 review added, where stated.
func comparePhase6(e *expectedFinding, a *rules.Finding) []string {
	var diffs []string
	diff := func(field string, want, got any) {
		w, _ := json.Marshal(want)
		g, _ := json.Marshal(got)
		if !bytes.Equal(w, g) {
			diffs = append(diffs, fmt.Sprintf("%s: want %s, got %s", field, w, g))
		}
	}
	if e.AlsoFixes != nil {
		got := a.AlsoFixes
		if got == nil {
			got = []rules.FindingRef{}
		}
		diff("also_fixes", *e.AlsoFixes, got)
	}
	if e.Uncuttable != nil {
		got := []expectedEdge{}
		for _, u := range a.Uncuttable {
			got = append(got, expectedEdge{Edge: u.Edge})
		}
		diff("uncuttable", *e.Uncuttable, got)
	}
	if e.RemediationStatus != "" {
		diff("remediation_status", e.RemediationStatus, a.RemediationStatus)
	}
	if e.SharedFix != nil {
		diff("shared_fix_possible", e.SharedFix, nonEmpty(a.SharedFix))
	}
	if e.WorstCasePath != nil {
		diff("worst_case_path", e.WorstCasePath, nonEmpty(a.WorstCasePath))
	}
	return diffs
}

// compareWithOpen checks the differences against
// testdata/open_mismatches.txt, the list waiting for review: any difference
// not on it, or any listed one that no longer occurs, fails.
func compareWithOpen(t *testing.T, report []string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "open_mismatches.txt"))
	if err != nil {
		t.Fatal(err)
	}
	open := map[string]bool{}
	for _, line := range strings.Split(string(data), string(rune(10))) {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			open[line] = true
		}
	}
	got := map[string]bool{}
	for _, line := range report {
		got[line] = true
		if !open[line] {
			t.Error("new difference: " + line)
		}
	}
	for line := range open {
		if !got[line] {
			t.Error("listed difference no longer occurs (remove it from testdata/open_mismatches.txt): " + line)
		}
	}
}
