package report

import (
	"io"

	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/rules"
	"github.com/r3oof-900/clapa/internal/version"
	"github.com/r3oof-900/clapa/pkg/schema"
)

// Reporter renders a report document in one format.
type Reporter interface {
	Write(w io.Writer, r *schema.Report) error
}

// Input is everything a report is built from.
type Input struct {
	Findings          []rules.Finding
	Registry          *rules.Registry
	CatalogVersion    string
	IntendedAccess    []schema.IntendedAccess
	Notes             []schema.Note
	Gaps              []coverage.Gap
	Collected         int
	GapsOverTolerance int
	ExitCode          int
	Graph             schema.Graph
	AssumeCompromised bool
	FailOn            string
}

// Build makes the versioned report document.
func Build(in *Input) *schema.Report {
	v := version.Get()
	r := &schema.Report{
		Schema: schema.Version,
		Tool: schema.Tool{
			Name: "clapa", Version: v.Version, Commit: v.Commit, RuleCatalog: in.CatalogVersion,
			InformationURI: "https://github.com/r3oof-900/clapa",
		},
		ThreatModel:    schema.ThreatModel{AssumeCompromised: in.AssumeCompromised, FailOn: in.FailOn},
		Summary:        schema.Summary{Findings: len(in.Findings), BySeverity: map[string]int{}},
		Findings:       []schema.Finding{},
		IntendedAccess: in.IntendedAccess,
		Coverage:       schema.Coverage{Collected: in.Collected, GapsOverTolerance: in.GapsOverTolerance, Gaps: []schema.Gap{}, Notes: in.Notes},
		Graph:          in.Graph,
		ExitCode:       in.ExitCode,
	}
	if r.IntendedAccess == nil {
		r.IntendedAccess = []schema.IntendedAccess{}
	}
	if r.Coverage.Notes == nil {
		r.Coverage.Notes = []schema.Note{}
	}
	for i := range in.Findings {
		f := finding(&in.Findings[i])
		r.Findings = append(r.Findings, f)
		r.Summary.BySeverity[f.Severity]++
		switch f.Status {
		case rules.StatusConfirmedUnlessDenied:
			r.Summary.ConfirmedUnlessDenied++
		case rules.StatusUnconfirmed:
			r.Summary.Unconfirmed++
		}
	}
	for i := range in.Gaps {
		g := &in.Gaps[i]
		r.Coverage.Gaps = append(r.Coverage.Gaps, schema.Gap{
			Kind: string(g.Kind), Source: g.Source, File: g.File, Line: g.Line, Address: g.Address,
			Account: g.Account, API: g.API, Detail: g.Detail,
		})
	}
	for _, rule := range in.Registry.Rules() {
		m := rule.Meta()
		refs := make([]string, len(m.References))
		for i, ref := range m.References {
			refs[i] = ref.URL
		}
		r.Rules = append(r.Rules, schema.Rule{
			ID: m.ID, Version: m.Version, Kind: m.Kind, Title: m.Title, Rationale: m.Rationale,
			Techniques: nonNil(m.Techniques), References: refs,
		})
	}
	return r
}

func finding(f *rules.Finding) schema.Finding {
	out := schema.Finding{
		Rule: f.Rule, RuleVersion: f.Version, Kind: f.Kind, Title: f.Title,
		Severity: f.Factors.Severity, Score: f.Factors.Score, Confirmed: f.Confirmed, Status: status(f), Undecided: f.Undecided, Confidence: f.Confidence,
		Factors: schema.Factors{
			Exposure: f.Factors.Exposure, Hops: f.Factors.Hops, Preconditions: f.Factors.Preconditions,
			Confidence: f.Factors.Confidence, Likelihood: f.Factors.Likelihood, Classification: f.Factors.Classification,
			BlastRadius: f.Factors.BlastRadius, Impact: f.Factors.Impact,
		},
		Entry: f.Entry, Jewel: f.Jewel, Resource: f.Resource, Path: f.Path, PathsFound: f.Paths, PathsTruncated: f.Truncated,
		Chokepoints: f.Chokepoints, CutCost: f.CutCost, NoFix: f.NoFix, AlternativeFix: f.Alternative, Fix: steps(f.Fix), OtherSideFix: steps(f.OtherSideFix), AlternativeFixDetail: steps(f.AlternativeDetail), SharedFixPossible: f.SharedFix,
		DefaultsUsed: []schema.Default{}, Evidence: f.Evidence, Fingerprint: f.Fingerprint, Location: location(&f.Location),
		WorstCasePath: f.WorstCasePath, RemediationStatus: f.RemediationStatus,
	}
	if f.Kind == rules.KindPath {
		also, unc := make([]schema.FindingRef, 0, len(f.AlsoFixes)), make([]schema.UncuttableEdge, 0, len(f.Uncuttable))
		for _, r := range f.AlsoFixes {
			also = append(also, schema.FindingRef(r))
		}
		for _, u := range f.Uncuttable {
			unc = append(unc, schema.UncuttableEdge(u))
		}
		out.AlsoFixes, out.Uncuttable = &also, &unc
	}
	for _, key := range f.DefaultsUsed {
		d, _ := model.LookupDefault(key)
		out.DefaultsUsed = append(out.DefaultsUsed, schema.Default{
			Key: key, Setting: d.Setting, Value: d.Value, ValueSource: "default", Reference: d.Reference,
		})
	}
	return out
}

func location(l *model.SourceLocation) *schema.Location {
	if l.IsZero() {
		return nil
	}
	start, end := l.Lines()
	return &schema.Location{File: l.File(), StartLine: start, EndLine: end, Address: l.Address(), ARN: l.ARN(), API: l.API()}
}

func steps(fs []rules.FixStep) []schema.FixStep {
	out := make([]schema.FixStep, len(fs))
	for i, f := range fs {
		out[i] = schema.FixStep(f)
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// status: a finding's status; a rule that does not set one is confirmed
// when Confirmed (posture rules), unconfirmed otherwise.
func status(f *rules.Finding) string {
	switch {
	case f.Status != "":
		return f.Status
	case f.Confirmed:
		return rules.StatusConfirmed
	}
	return rules.StatusUnconfirmed
}
