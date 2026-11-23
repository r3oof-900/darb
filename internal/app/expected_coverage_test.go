package app

import (
	"fmt"
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/access"
	"github.com/r3oof-900/darb/internal/coverage"
)

// The notes and gaps an expected file states (expected.json fields notes,
// notes_absent, gaps, gaps_absent).

type expectedNote struct {
	Subject  string   `json:"subject"`
	Kind     string   `json:"kind"`
	Contains []string `json:"contains"`
}

func containsAll(s string, parts []string) bool {
	return !slices.ContainsFunc(parts, func(p string) bool { return !strings.Contains(s, p) })
}

// compareCoverage checks the notes and gaps an expected file states.
func compareCoverage(exp *expectedFile, a *Analysis) []string {
	var out []string
	for _, n := range exp.Notes {
		if !slices.ContainsFunc(a.Notes, func(got access.Note) bool { return got.Subject == n.Subject && containsAll(got.Detail, n.Contains) }) {
			out = append(out, fmt.Sprintf("missing note %q containing %q", n.Subject, n.Contains))
		}
	}
	for _, subject := range exp.NotesAbsent {
		if slices.ContainsFunc(a.Notes, func(got access.Note) bool { return got.Subject == subject }) {
			out = append(out, fmt.Sprintf("note %q must be absent", subject))
		}
	}
	for _, g := range exp.Gaps {
		if !slices.ContainsFunc(a.Gaps, func(got coverage.Gap) bool { return string(got.Kind) == g.Kind && containsAll(got.Detail, g.Contains) }) {
			out = append(out, fmt.Sprintf("missing %s gap containing %q", g.Kind, g.Contains))
		}
	}
	for _, text := range exp.GapsAbsent {
		for i := range a.Gaps {
			if got := &a.Gaps[i]; strings.Contains(got.Detail, text) {
				out = append(out, fmt.Sprintf("gap must be absent: %s %s", got.Address, got.Detail))
			}
		}
	}
	return out
}
