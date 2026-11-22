package markdown

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/r3oof-900/darb/pkg/schema"
)

// MaxBytes bounds the comment: GitHub refuses a pull request comment over
// 65536 characters; this leaves room for a wrapper around it.
const MaxBytes = 60000

// Reporter writes a summary for a pull request comment: the counts, the
// attack paths by severity with their recommended fix, the
// misconfigurations, and the coverage. Every name from the input is a code
// span, so it cannot become a link, a mention or markup.
type Reporter struct {
	// Limit overrides MaxBytes (tests).
	Limit int
}

var severities = []string{"critical", "high", "medium", "low", "info"}

func rank(s string) int {
	if i := slices.Index(severities, s); i >= 0 {
		return i
	}
	return len(severities)
}

// code is an inline code span holding s literally: line breaks become
// spaces, table pipes are escaped (GitHub splits cells on them even in
// code), and the fence is longer than any backtick run in s.
func code(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ", "|", `\|`).Replace(s)
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") || longest > 0 {
		return fence + " " + s + " " + fence
	}
	return fence + s + fence
}

// Write renders r.
func (rep Reporter) Write(w io.Writer, r *schema.Report) error {
	limit := rep.Limit
	if limit == 0 {
		limit = MaxBytes
	}
	var head, tail strings.Builder
	header(&head, r)
	coverage(&tail, r)
	fs := slices.Clone(r.Findings)
	slices.SortStableFunc(fs, func(a, b schema.Finding) int {
		if d := rank(a.Severity) - rank(b.Severity); d != 0 {
			return d
		}
		return b.Score - a.Score
	})
	body := findings(fs, limit-head.Len()-tail.Len()-200)
	_, err := io.WriteString(w, head.String()+body+tail.String())
	return err
}

func header(b *strings.Builder, r *schema.Report) {
	fmt.Fprintf(b, "## darb: %d findings\n\n", r.Summary.Findings)
	b.WriteString("| " + strings.Join(severities, " | ") + " |\n|" + strings.Repeat("---|", len(severities)) + "\n|")
	for _, s := range severities {
		fmt.Fprintf(b, " %d |", r.Summary.BySeverity[s])
	}
	fmt.Fprintf(b, "\n\nExit code %d (fail on %s). %d confirmed unless denied, %d unconfirmed: a severity is the worst case of every unknown.\n\n",
		r.ExitCode, r.ThreatModel.FailOn, r.Summary.ConfirmedUnlessDenied, r.Summary.Unconfirmed)
	if r.Coverage.Collected == 0 {
		b.WriteString("> **Nothing was scanned: this is not a clean result.**\n\n")
	}
	if e := r.ExecutiveSummary; e != nil {
		fmt.Fprintf(b, "> %s: %s\n\n", e.Label(), code(e.Summary))
	}
}

func pathBlock(f *schema.Finding) string {
	var b strings.Builder
	status := ""
	if f.Status != "confirmed" {
		status = " · " + strings.ReplaceAll(f.Status, "_", " ")
	}
	fmt.Fprintf(&b, "**%s %d** · %s · %s%s\n\n", strings.ToUpper(f.Severity), f.Score, f.Rule, f.Title, status)
	fmt.Fprintf(&b, "%s → %s\n\n", code(f.Entry), code(f.Jewel))
	b.WriteString(fix(f))
	fmt.Fprintf(&b, "<sub>fingerprint %s</sub>\n\n", code(f.Fingerprint))
	return b.String()
}

// fix is the recommended fix: the first verified fix when the report has
// them (scan --fixes), otherwise the cheapest cut, not yet verified.
func fix(f *schema.Finding) string {
	if f.NoFix {
		return "No fix within the configured constraints.\n\n"
	}
	if rm := f.Remediation; rm != nil && len(rm.Fixes) > 0 {
		x := rm.Fixes[0]
		verified := "not verified"
		if x.VerifiedInMemory && x.VerifiedOnFiles {
			verified = "verified in memory and on the patched files"
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Recommended fix (%s, %s):\n", x.Strategy, verified)
		for _, c := range x.Changes {
			fmt.Fprintf(&b, "- %s: %s\n", c.Kind, code(c.Why))
		}
		if x.Suggestion != "" {
			fmt.Fprintf(&b, "- %s\n", code(x.Suggestion))
		}
		return b.String() + "\n"
	}
	if len(f.Fix) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Recommended fix (cost %d, not verified; `darb remediate` verifies it):\n", f.CutCost)
	for _, s := range f.Fix {
		if s.Kind == "resolve" {
			fmt.Fprintf(&b, "- resolve %s first: %s\n", code(s.Policy), code(s.Resolve))
			continue
		}
		fmt.Fprintf(&b, "- %s the grant in %s (%s side) to break %s\n", s.Kind, code(s.Policy), s.Side, code(s.Edge))
	}
	return b.String() + "\n"
}

func postureRow(f *schema.Finding) string {
	return fmt.Sprintf("| %s | %d | %s %s | %s |\n", strings.ToUpper(f.Severity), f.Score, f.Rule, strings.ReplaceAll(f.Title, "|", `\|`), code(f.Resource))
}

func coverage(b *strings.Builder, r *schema.Report) {
	c := r.Coverage
	fmt.Fprintf(b, "### Coverage\n\n%d inputs collected; %d coverage gaps, %d over tolerance; graph: %d nodes, %d edges.\n",
		c.Collected, len(c.Gaps), c.GapsOverTolerance, r.Graph.Nodes, r.Graph.Edges)
	for _, n := range c.Notes {
		fmt.Fprintf(b, "- %s %s\n", n.Kind, code(n.Subject))
	}
}

// findings renders the attack paths, then the misconfigurations, within
// budget bytes (the room left by the fixed parts and the "more" line),
// and says how many did not fit.
func findings(fs []schema.Finding, budget int) string {
	var paths, posture []string
	for i := range fs {
		if fs[i].Resource == "" {
			paths = append(paths, pathBlock(&fs[i]))
		} else {
			posture = append(posture, postureRow(&fs[i]))
		}
	}
	var body strings.Builder
	shown := 0
	add := func(items []string) bool {
		for _, s := range items {
			if body.Len()+len(s) > budget {
				return false
			}
			body.WriteString(s)
			shown++
		}
		return true
	}
	full := true
	if len(paths) > 0 {
		body.WriteString("### Attack paths\n\n")
		full = add(paths)
	}
	if full && len(posture) > 0 {
		body.WriteString("### Misconfigurations\n\n| Severity | Score | Rule | Resource |\n|---|---|---|---|\n")
		add(posture)
		body.WriteString("\n")
	}
	if more := len(fs) - shown; more > 0 {
		fmt.Fprintf(&body, "\n**%d more findings in the full report** (`darb scan --format html` or `--format json`).\n\n", more)
	}
	return body.String()
}
