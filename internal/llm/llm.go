// Package llm is the optional explanation layer (DESIGN.md §10). Off by
// default; with --llm a provider explains an already-computed finding, or
// writes an executive summary, in plain words. It never decides a verdict,
// a score or a fix: its output is shown beside the engine's, labelled
// "AI-generated explanation", and escaped like any untrusted text. What
// leaves the machine is structured evidence from the report (never a file
// of the input), every string passed through the secret redactor, and,
// with --llm-redact-identifiers, identifiers replaced by tokens that are
// put back locally. Any failure (no key, a timeout, a refusal, an answer
// that does not match the schema) falls back to template text with a note.
package llm

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/r3oof-900/clapa/internal/llm/pseudonymize"
	"github.com/r3oof-900/clapa/internal/redact"
	"github.com/r3oof-900/clapa/pkg/schema"
)

// Kinds of request.
const (
	KindFinding = "finding" // explain one finding
	KindSummary = "summary" // an executive summary of the report
)

// Step is one change of a finding's cheapest fix.
type Step struct {
	Edge    string `json:"edge"`
	Side    string `json:"side"`
	Kind    string `json:"kind"`
	Policy  string `json:"policy"`
	Resolve string `json:"resolve,omitempty"`
}

// Evidence is what the provider is given of one finding: structured
// fields of the report, nothing else.
type Evidence struct {
	Rule       string   `json:"rule"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Score      int      `json:"score"`
	Status     string   `json:"status"`
	Entry      string   `json:"entry,omitempty"`
	Jewel      string   `json:"jewel,omitempty"`
	Resource   string   `json:"resource,omitempty"`
	Path       []string `json:"path,omitempty"`
	Undecided  []string `json:"undecided,omitempty"`
	Fix        []Step   `json:"cheapest_fix,omitempty"`
	Strategy   string   `json:"recommended_strategy,omitempty"`
	Defaults   []string `json:"relies_on_defaults,omitempty"`
	Unverified bool     `json:"fix_not_verified,omitempty"`
}

// ExplainRequest is one request: a finding (one Evidence) or a summary
// (every finding's).
type ExplainRequest struct {
	Kind     string     `json:"kind"`
	Findings []Evidence `json:"findings"`
}

// Explanation is what comes back, in three parts: what it is, how an
// attacker uses it, what the fix does.
type Explanation struct {
	Summary string `json:"summary"`
	Attack  string `json:"attack"`
	Fix     string `json:"fix"`
	// AIGenerated: written by the provider (Model); otherwise the template,
	// and Note says why.
	AIGenerated bool   `json:"ai_generated"`
	Model       string `json:"model,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Explainer is a provider.
type Explainer interface {
	Explain(ctx context.Context, req ExplainRequest) (Explanation, error)
	Model() string
}

// EvidenceOf is a finding as the provider sees it.
func EvidenceOf(f *schema.Finding) Evidence {
	e := Evidence{
		Rule: f.Rule, Title: f.Title, Severity: f.Severity, Score: f.Score, Status: f.Status,
		Entry: f.Entry, Jewel: f.Jewel, Resource: f.Resource, Path: f.Path, Undecided: f.Undecided,
	}
	for _, s := range f.Fix {
		e.Fix = append(e.Fix, Step{Edge: s.Edge, Side: s.Side, Kind: s.Kind, Policy: s.Policy, Resolve: s.Resolve})
	}
	for _, d := range f.DefaultsUsed {
		e.Defaults = append(e.Defaults, d.Setting+" = "+d.Value)
	}
	if f.Remediation != nil && len(f.Remediation.Fixes) > 0 {
		e.Strategy = f.Remediation.Fixes[0].Strategy
	} else {
		e.Unverified = len(f.Fix) > 0
	}
	return e
}

// Prepare redacts every string of the request and, with a mapping,
// replaces identifiers by tokens.
func Prepare(req ExplainRequest, m *pseudonymize.Mapping) ExplainRequest {
	clean := func(s string) string {
		s = redact.Redact(s)
		if m != nil {
			s = m.Apply(s)
		}
		return s
	}
	list := func(xs []string) []string {
		out := make([]string, len(xs))
		for i, x := range xs {
			out[i] = clean(x)
		}
		return out
	}
	out := ExplainRequest{Kind: req.Kind}
	for i := range req.Findings {
		e := &req.Findings[i]
		c := Evidence{
			Rule: e.Rule, Title: clean(e.Title), Severity: e.Severity, Score: e.Score, Status: e.Status,
			Entry: clean(e.Entry), Jewel: clean(e.Jewel), Resource: clean(e.Resource),
			Path: list(e.Path), Undecided: list(e.Undecided), Defaults: list(e.Defaults),
			Strategy: e.Strategy, Unverified: e.Unverified,
		}
		for _, s := range e.Fix {
			c.Fix = append(c.Fix, Step{Edge: clean(s.Edge), Side: s.Side, Kind: s.Kind, Policy: clean(s.Policy), Resolve: clean(s.Resolve)})
		}
		out.Findings = append(out.Findings, c)
	}
	return out
}

// Explain asks the provider (nil: none) and always returns an explanation:
// the provider's, identifiers restored and control characters removed, or
// the template with a note saying why.
func Explain(ctx context.Context, p Explainer, req ExplainRequest, m *pseudonymize.Mapping) Explanation {
	if p == nil {
		t := Template(req)
		t.Note = "no LLM provider enabled (--llm): template text"
		return t
	}
	got, err := p.Explain(ctx, Prepare(req, m))
	if err == nil {
		err = valid(&got)
	}
	if err != nil {
		t := Template(req)
		t.Note = "the LLM explanation failed (" + redact.Redact(err.Error()) + "): template text"
		return t
	}
	restore := func(s string) string {
		if m != nil {
			s = m.Restore(s)
		}
		return printable(s)
	}
	return Explanation{
		Summary: restore(got.Summary), Attack: restore(got.Attack), Fix: restore(got.Fix),
		AIGenerated: true, Model: p.Model(),
	}
}

// maxField bounds each part of an answer (the token cap bounds the whole).
const maxField = 4000

func valid(e *Explanation) error {
	if strings.TrimSpace(e.Summary) == "" {
		return fmt.Errorf("an empty summary")
	}
	for _, s := range []string{e.Summary, e.Attack, e.Fix} {
		if len(s) > maxField {
			return fmt.Errorf("an answer longer than %d characters", maxField)
		}
	}
	return nil
}

// printable drops control characters (terminal escapes) but keeps line
// breaks and tabs.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || !unicode.IsControl(r) {
			return r
		}
		return -1
	}, s)
}

// Template is the explanation written without a provider, from the
// evidence alone.
func Template(req ExplainRequest) Explanation {
	if req.Kind == KindSummary {
		return summaryTemplate(req.Findings)
	}
	if len(req.Findings) == 0 {
		return Explanation{Summary: "No finding."}
	}
	e := req.Findings[0]
	out := Explanation{}
	switch {
	case e.Resource != "":
		out.Summary = fmt.Sprintf("%s (%s, score %d): %s, on %s.", e.Rule, e.Severity, e.Score, e.Title, e.Resource)
	default:
		out.Summary = fmt.Sprintf("%s (%s, score %d): %s: %s reaches %s.", e.Rule, e.Severity, e.Score, e.Title, e.Entry, e.Jewel)
		if len(e.Path) > 0 {
			out.Attack = "From the entry, an attacker follows " + fmt.Sprint(len(e.Path)) + " steps: " + strings.Join(e.Path, "; then ") + "."
		}
	}
	if e.Status != "confirmed" && e.Status != "" {
		out.Summary += " Status " + strings.ReplaceAll(e.Status, "_", " ") + ": the severity is the worst case of what is not known."
	}
	var steps []string
	for _, s := range e.Fix {
		if s.Kind == "resolve" {
			steps = append(steps, "decide "+s.Policy+" ("+s.Resolve+")")
			continue
		}
		steps = append(steps, s.Kind+" the grant in "+s.Policy+" ("+s.Side+" side) to break "+s.Edge)
	}
	if len(steps) > 0 {
		out.Fix = "The cheapest fix: " + strings.Join(steps, "; ") + "."
	}
	return out
}

func summaryTemplate(fs []Evidence) Explanation {
	paths, posture := 0, 0
	worst := ""
	for i := range fs {
		f := &fs[i]
		if f.Resource != "" {
			posture++
		} else {
			paths++
		}
		if worst == "" || rank(f.Severity) < rank(worst) {
			worst = f.Severity
		}
	}
	if len(fs) == 0 {
		return Explanation{Summary: "No finding."}
	}
	return Explanation{Summary: fmt.Sprintf("%d attack path(s) to crown-jewel data and %d misconfiguration(s); the most severe is %s.", paths, posture, worst)}
}

func rank(s string) int {
	for i, v := range []string{"critical", "high", "medium", "low", "info"} {
		if v == s {
			return i
		}
	}
	return 5
}
