package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/r3oof-900/clapa/internal/config"
	"github.com/r3oof-900/clapa/internal/findings"
	"github.com/r3oof-900/clapa/internal/rules"
	"github.com/r3oof-900/clapa/internal/safeio"
	"github.com/r3oof-900/clapa/pkg/schema"
)

// Triage is what the operator decided about earlier results: suppressions
// (.clapa-ignore.yaml) and a baseline (a previous JSON report).
type Triage struct {
	Suppressions []config.Suppression
	// Baseline is the previous report (nil: no --baseline); BaselineFile
	// names it in the report.
	Baseline     *schema.Report
	BaselineFile string
	Now          time.Time
}

// LoadIgnore reads the suppression file: rel under root ("" for the
// default .clapa-ignore.yaml, which may be absent). A suppression without
// its reason, owner or expiry is a configuration error (exit 2).
func LoadIgnore(root, rel string) ([]config.Suppression, error) {
	required := rel != ""
	if rel == "" {
		rel = ".clapa-ignore.yaml"
	}
	data, err := safeio.ReadFile(root, rel, safeio.DefaultLimits())
	switch {
	case err == nil:
		return config.ParseIgnore(data)
	case !required && errors.Is(err, fs.ErrNotExist):
		return nil, nil
	}
	return nil, fmt.Errorf("%w: %s: %w", config.ErrInvalid, rel, err)
}

// ErrBaseline is returned for a baseline that is not a clapa-report/v1 JSON report.
var ErrBaseline = errors.New("not a " + schema.Version + " JSON report")

// LoadBaseline reads a previous JSON report (a path relative to root).
func LoadBaseline(root, rel string) (*schema.Report, error) {
	data, err := safeio.ReadFile(root, rel, safeio.DefaultLimits())
	if err != nil {
		return nil, fmt.Errorf("%w: --baseline %s: %w", config.ErrInvalid, rel, err)
	}
	var r schema.Report
	if err := json.Unmarshal(data, &r); err != nil || r.Schema != schema.Version {
		return nil, fmt.Errorf("%w: --baseline %s: %w", config.ErrInvalid, rel, ErrBaseline)
	}
	return &r, nil
}

// ApplyTriage removes the suppressed findings (an expired suppression does
// not apply: its finding fires again and is listed), then, with a
// baseline, keeps only the new findings; the exit code is recomputed from
// what is left.
func ApplyTriage(a *Analysis, t *Triage, failOn string) {
	sups := make([]findings.Suppression, 0, len(t.Suppressions))
	for _, s := range t.Suppressions {
		exp, _ := time.Parse(time.DateOnly, s.Expires) // validated by config.ParseIgnore
		// A suppression holds through its expiry date (inclusive).
		sups = append(sups, findings.Suppression{Fingerprint: s.Fingerprint, Reason: s.Reason, Owner: s.Owner, Expires: exp.Add(24*time.Hour - time.Nanosecond)})
	}
	all := a.Findings
	active, suppressed, expired := findings.Apply(all, sups, t.Now)
	present := map[string]bool{}
	for i := range active {
		present[active[i].Fingerprint] = true
	}
	for i := range suppressed {
		s := &suppressed[i]
		a.Suppressed = append(a.Suppressed, schema.SuppressedFinding{
			Fingerprint: s.Finding.Fingerprint, Rule: s.Finding.Rule, Severity: s.Finding.Factors.Severity,
			Entry: s.Finding.Entry, Jewel: s.Finding.Jewel, Resource: s.Finding.Resource,
			Reason: s.Suppression.Reason, Owner: s.Suppression.Owner, Expires: s.Suppression.Expires.Format(time.DateOnly),
		})
	}
	for _, s := range expired {
		a.Expired = append(a.Expired, schema.ExpiredSuppression{
			Fingerprint: s.Fingerprint, Reason: s.Reason, Owner: s.Owner, Expires: s.Expires.Format(time.DateOnly), Fires: present[s.Fingerprint],
		})
	}
	a.Findings = active
	if t.Baseline != nil {
		a.Findings, a.Baseline = diffBaseline(active, all, t.Baseline, t.BaselineFile)
	}
	a.ExitCode = findings.ExitCode(a.Findings, failOn, a.Collected, a.GapsCounted)
}

// diffBaseline: new are the active findings the baseline lacks; resolved
// the baseline's findings the scan no longer has at all (a suppressed
// finding is still there, so it is not resolved).
func diffBaseline(active, all []rules.Finding, base *schema.Report, file string) ([]rules.Finding, *schema.Baseline) {
	fps := make([]string, 0, len(base.Findings))
	byFP := map[string]*schema.Finding{}
	for i := range base.Findings {
		fps = append(fps, base.Findings[i].Fingerprint)
		byFP[base.Findings[i].Fingerprint] = &base.Findings[i]
	}
	added, _ := findings.Diff(active, fps)
	_, resolved := findings.Diff(all, fps)
	b := &schema.Baseline{File: file, New: len(added), Unchanged: len(active) - len(added), Resolved: []schema.ResolvedItem{}}
	for _, fp := range resolved {
		f := byFP[fp]
		b.Resolved = append(b.Resolved, schema.ResolvedItem{Fingerprint: fp, Rule: f.Rule, Entry: f.Entry, Jewel: f.Jewel, Resource: f.Resource})
	}
	return added, b
}
