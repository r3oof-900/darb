package findings

import (
	"testing"
	"time"

	"github.com/r3oof-900/darb/internal/rules"
	"github.com/r3oof-900/darb/internal/scoring"
)

func TestFingerprint(t *testing.T) {
	a := Fingerprint("DARB-PATH-001", "1", "entry", "jewel")
	for _, other := range []string{
		Fingerprint("DARB-PATH-002", "1", "entry", "jewel"),
		Fingerprint("DARB-PATH-001", "2", "entry", "jewel"),
		Fingerprint("DARB-PATH-001", "1", "other", "jewel"),
		Fingerprint("DARB-PATH-001", "1", "entry", "other"),
		PostureFingerprint("DARB-PATH-001", "1", "entry"),
	} {
		if other == a {
			t.Error("a different rule, version, entry or jewel must change the fingerprint")
		}
	}
}

func TestSuppressionsBaselineExitCode(t *testing.T) {
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	fs := []rules.Finding{
		{Fingerprint: "a", Factors: scoringOf("critical")},
		{Fingerprint: "b", Factors: scoringOf("low")},
	}
	active, suppressed, expired := Apply(fs, []Suppression{
		{Fingerprint: "a", Reason: "accepted", Owner: "team", Expires: now.AddDate(0, 1, 0)},
		{Fingerprint: "b", Reason: "old", Owner: "team", Expires: now.AddDate(0, -1, 0)},
	}, now)
	if len(active) != 1 || active[0].Fingerprint != "b" || len(suppressed) != 1 || len(expired) != 1 {
		t.Fatalf("active %v suppressed %v expired %v", active, suppressed, expired)
	}
	added, resolved := Diff(fs, []string{"a", "gone"})
	if len(added) != 1 || added[0].Fingerprint != "b" || len(resolved) != 1 || resolved[0] != "gone" {
		t.Fatalf("added %v resolved %v", added, resolved)
	}
	cases := []struct {
		fs                  []rules.Finding
		collected, gaps, ec int
	}{
		{fs, 5, 0, ExitFindings},
		{fs[1:], 5, 0, ExitOK},
		{fs[1:], 5, 2, ExitIncomplete},
		{nil, 0, 0, ExitIncomplete},
	}
	for i, c := range cases {
		if got := ExitCode(c.fs, "high", c.collected, c.gaps); got != c.ec {
			t.Errorf("case %d: exit %d, want %d", i, got, c.ec)
		}
	}
	if !AtOrAbove("critical", "high") || AtOrAbove("medium", "high") || !AtOrAbove("high", "high") {
		t.Error("AtOrAbove")
	}
}

func scoringOf(severity string) scoring.Factors { return scoring.Factors{Severity: severity} }
