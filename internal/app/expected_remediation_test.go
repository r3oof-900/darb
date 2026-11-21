package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/r3oof-900/clapa/internal/rules"
)

// compareRemediation runs the remediation of a finding and compares it.
func compareRemediation(t *testing.T, in *Inputs, l *Loaded, a *Analysis, e *expectedFinding, f *rules.Finding) []string {
	t.Helper()
	r, err := Remediate(t.Context(), in, l, a, f.Fingerprint)
	if err != nil {
		return []string{"remediation: " + err.Error()}
	}
	got := expectedRemediation{Missing: len(r.Plan.Missing) > 0, Note: r.Note}
	if !got.Missing {
		for _, x := range append([]*Remediation{r}, r.Others...) {
			got.Order = append(got.Order, x.Plan.Strategy)
			got.Verified = append(got.Verified, x.Accepted())
		}
	}
	w, _ := json.Marshal(e.Remediation)
	g, _ := json.Marshal(got)
	if !bytes.Equal(w, g) {
		return []string{fmt.Sprintf("remediation: want %s, got %s", w, g)}
	}
	return nil
}
