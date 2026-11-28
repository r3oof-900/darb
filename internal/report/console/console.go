// Package console writes the report for a terminal: a summary, then each
// finding with its path, its cheapest fix and what it relies on. It never
// says "secure": an empty result states the coverage it rests on.
package console

import (
	"fmt"
	"io"
	"strings"

	"github.com/r3oof-900/darb/pkg/schema"
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
	p.printf("darb %s (rule catalog %s), threat model: assume compromised = %t, fail on %s\n",
		r.Tool.Version, r.Tool.RuleCatalog, r.ThreatModel.AssumeCompromised, r.ThreatModel.FailOn)
	p.printf("%d inputs collected; %d gaps beyond tolerance; graph %d nodes, %d edges\n\n",
		r.Coverage.Collected, r.Coverage.GapsOverTolerance, r.Graph.Nodes, r.Graph.Edges)
	if r.Coverage.Collected == 0 {
		p.printf("NOTHING WAS SCANNED: no input produced data. This is not a clean result.\n")
	}
	p.warnings(r.Coverage.Notes)
	p.triage(r)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := r.Summary.BySeverity[sev]; n > 0 {
			p.printf("%-8s %d\n", sev, n)
		}
	}
	p.printf("confirmed unless denied %d, unconfirmed %d (severities are the worst case of every unknown)\n\n", r.Summary.ConfirmedUnlessDenied, r.Summary.Unconfirmed)
	if e := r.ExecutiveSummary; e != nil {
		p.explanation("", e)
		p.printf("\n")
	}
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

// warnings prints the notes a reader must see before trusting the result:
// unknown grants (managed policies missing from the snapshot), incomplete
// or unknown service coverage, TLS verification off.
func (p *printer) warnings(notes []schema.Note) {
	n := 0
	for _, note := range notes {
		switch note.Kind {
		case schema.NoteManagedPolicies, schema.NoteInsecureTLS, schema.NoteUnclassified, schema.NoteIntendedOtherRoute:
			p.printf("WARNING: %s\n", note.Detail)
		case schema.NoteServiceCoverage:
			p.printf("WARNING: coverage of %s: %s\n", note.Subject, note.Detail)
		default:
			continue
		}
		n++
	}
	if n > 0 {
		p.printf("\n")
	}
}

// triage prints the suppressions and the baseline comparison: an expired
// suppression is a warning (its finding fires again).
func (p *printer) triage(r *schema.Report) {
	for _, e := range r.ExpiredSuppressions {
		fires := "its finding is no longer present"
		if e.Fires {
			fires = "its finding fires again"
		}
		p.printf("WARNING: the suppression of %s (owner %s) expired on %s: %s\n", e.Fingerprint, e.Owner, e.Expires, fires)
	}
	if len(r.Suppressed) > 0 {
		p.printf("suppressed %d finding(s) (.darb-ignore.yaml; listed in the JSON report)\n", len(r.Suppressed))
	}
	if b := r.Baseline; b != nil {
		p.printf("baseline %s: %d new, %d unchanged (not shown), %d resolved\n", b.File, b.New, b.Unchanged, len(b.Resolved))
		for _, res := range b.Resolved {
			p.printf("  resolved %s %s%s%s\n", res.Rule, res.Entry, arrow(res.Jewel), res.Resource)
		}
	}
	if len(r.ExpiredSuppressions) > 0 || len(r.Suppressed) > 0 || r.Baseline != nil {
		p.printf("\n")
	}
}

func arrow(jewel string) string {
	if jewel == "" {
		return ""
	}
	return " -> " + jewel
}

func finding(p *printer, f *schema.Finding) {
	confirmed := ""
	switch f.Status {
	case "confirmed_unless_denied":
		confirmed = " CONFIRMED UNLESS DENIED (confidence " + f.Confidence + ")"
	case "unconfirmed":
		confirmed = " UNCONFIRMED (confidence " + f.Confidence + ")"
	}
	p.printf("[%s %d]%s %s  %s\n", strings.ToUpper(f.Severity), f.Score, confirmed, f.Rule, f.Title)
	if f.Resource != "" {
		p.resource(f)
	} else {
		p.path(f)
	}
	if e := f.Explanation; e != nil {
		p.explanation("    ", e)
	}
	if len(f.Chokepoints) > 0 {
		p.printf("    cheapest fix (cost %d): %s\n", f.CutCost, strings.Join(f.Chokepoints, "; "))
	}
	if f.NoFix {
		p.printf("    no fix within the configured constraints\n")
	}
	p.fixes(f)
	if f.RemediationStatus == "partial_pending_resolution" {
		p.printf("    resolve the unknowns listed, then rescan: the fix may need more steps once they are known\n")
	}
	for _, r := range f.SharedFixPossible {
		p.printf("    shared fix possible: one change to the policy of %s breaks several cut edges\n", r)
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

// fixes prints the chosen side of each cut edge and the other sides.
func (p *printer) fixes(f *schema.Finding) {
	for _, s := range f.Fix {
		p.step("      ", &s)
	}
	for _, s := range f.OtherSideFix {
		p.step("      or the ", &s)
	}
}

// step prints one fix: its side and kind, the policy to change and its cost;
// a revoke removes an explicit grant, so it carries a warning (SCORING.md §4.1).
func (p *printer) step(prefix string, s *schema.FixStep) {
	if s.Kind == "resolve" {
		p.printf("%s%s side, resolve: %s is unknown: %s (no change)\n", prefix, s.Side, s.Policy, s.Resolve)
		return
	}
	if key, grant, ok := strings.Cut(s.Policy, "#grant/"); ok && !strings.Contains(grant, ", ") {
		// A KMS grant (model.GrantDocMarker): it is revoked, not changed.
		p.printf("%s%s side, %s: revoke the KMS grant %s on %s (cost %d)\n", prefix, s.Side, s.Kind, grant, key, s.Cost)
	} else {
		p.printf("%s%s side, %s: change %s (cost %d)\n", prefix, s.Side, s.Kind, s.Policy, s.Cost)
	}
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
	if f.JewelClassification == "unclassified" {
		p.printf("    the jewel has no classification (unclassified): tag it or list it in crown_jewels.explicit\n")
	}
	for _, u := range f.Undecided {
		p.printf("    undecided: %s\n", u)
	}
	for _, step := range f.Path {
		p.printf("      %s\n", step)
	}
}

// explanation prints an explanation under its label (DESIGN.md §10).
func (p *printer) explanation(indent string, e *schema.Explanation) {
	p.printf("%s%s:\n", indent, e.Label())
	for _, part := range []struct{ name, text string }{{"", e.Summary}, {"the attack: ", e.Attack}, {"the fix: ", e.Fix}} {
		if part.text != "" {
			p.printf("%s  %s%s\n", indent, part.name, strings.ReplaceAll(part.text, "\n", "\n"+indent+"  "))
		}
	}
}
