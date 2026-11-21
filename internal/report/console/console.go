// Package console writes the report for a terminal: a summary, then each
// finding with its path, its cheapest fix and what it relies on. It never
// says "secure": an empty result states the coverage it rests on.
package console

import (
	"fmt"
	"io"
	"strings"

	"github.com/r3oof-900/clapa/pkg/schema"
)

// Reporter writes plain text.
type Reporter struct{}

type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

// Write renders r.
func (Reporter) Write(w io.Writer, r *schema.Report) error {
	p := &printer{w: w}
	p.printf("clapa %s (rule catalog %s), threat model: assume compromised = %t, fail on %s\n",
		r.Tool.Version, r.Tool.RuleCatalog, r.ThreatModel.AssumeCompromised, r.ThreatModel.FailOn)
	p.printf("%d inputs collected; %d gaps beyond tolerance; graph %d nodes, %d edges\n\n",
		r.Coverage.Collected, r.Coverage.GapsOverTolerance, r.Graph.Nodes, r.Graph.Edges)
	if r.Coverage.Collected == 0 {
		p.printf("NOTHING WAS SCANNED: no input produced data. This is not a clean result.\n")
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := r.Summary.BySeverity[sev]; n > 0 {
			p.printf("%-8s %d\n", sev, n)
		}
	}
	p.printf("unconfirmed %d\n\n", r.Summary.Unconfirmed)
	for i := range r.Findings {
		finding(p, &r.Findings[i])
	}
	for _, ia := range r.IntendedAccess {
		p.printf("intended access %s %s %s: %s %s\n", ia.Principal, ia.Action, ia.Resource, ia.Status, ia.Detail)
	}
	if len(r.Findings) == 0 && r.Coverage.Collected > 0 {
		p.printf("No findings at or above any threshold in what was scanned. %d coverage gaps are listed in the JSON report.\n", len(r.Coverage.Gaps))
	}
	p.printf("exit code %d\n", r.ExitCode)
	return p.err
}

func finding(p *printer, f *schema.Finding) {
	confirmed := ""
	if !f.Confirmed {
		confirmed = " UNCONFIRMED"
	}
	p.printf("[%s %d]%s %s  %s\n", strings.ToUpper(f.Severity), f.Score, confirmed, f.Rule, f.Title)
	if f.Resource != "" {
		p.resource(f)
	} else {
		p.path(f)
	}
	if len(f.Chokepoints) > 0 {
		p.printf("    cheapest fix (cost %d): %s\n", f.CutCost, strings.Join(f.Chokepoints, "; "))
	}
	if f.NoFix {
		p.printf("    no fix within the configured constraints\n")
	}
	for _, s := range f.Fix {
		p.step("      ", &s)
	}
	for _, s := range f.OtherSideFix {
		p.step("      or the ", &s)
	}
	for _, r := range f.SharedFixPossible {
		p.printf("    shared fix possible: one change to the policy of %s breaks several cut edges; the cost counts edges\n", r)
	}
	if len(f.AlternativeFixDetail) == 0 {
		for _, alt := range f.AlternativeFix {
			p.printf("    alternative fix: %s\n", alt)
		}
	}
	for _, s := range f.AlternativeFixDetail {
		p.printf("    alternative fix: %s\n", s.Edge)
		p.step("      ", &s)
	}
	for _, d := range f.DefaultsUsed {
		p.printf("    relies on a default: %s = %s (%s)\n", d.Setting, d.Value, d.Reference)
	}
	if f.Location != nil && f.Location.File != "" {
		p.printf("    at %s:%d\n", f.Location.File, f.Location.StartLine)
	}
	p.printf("    fingerprint %s\n\n", f.Fingerprint)
}

// step prints one fix: its side and kind, the policy to change and its cost;
// a revoke removes an explicit grant, so it carries a warning (SCORING.md §4.1).
func (p *printer) step(prefix string, s *schema.FixStep) {
	p.printf("%s%s side, %s: change %s (cost %d)\n", prefix, s.Side, s.Kind, s.Policy, s.Cost)
	if s.Kind == "revoke" {
		p.printf("%s  this removes an explicit grant; confirm it is not needed\n", strings.Repeat(" ", len(prefix)))
	}
}

// resource prints a posture finding's resource and the evidence: which
// statement or setting it is (a broad grant names its statement).
func (p *printer) resource(f *schema.Finding) {
	p.printf("    resource: %s\n", f.Resource)
	for _, ev := range f.Evidence {
		p.printf("    evidence: %s\n", ev)
	}
}

// path prints a path finding's entry and jewel, what would decide it when
// it is unconfirmed, and its steps.
func (p *printer) path(f *schema.Finding) {
	p.printf("    %s -> %s\n", f.Entry, f.Jewel)
	for _, u := range f.Undecided {
		p.printf("    undecided: %s\n", u)
	}
	for _, step := range f.Path {
		p.printf("      %s\n", step)
	}
}
