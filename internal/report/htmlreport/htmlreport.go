// Package htmlreport renders the self-contained HTML report (DESIGN.md §11,
// THREAT_MODEL.md): one file, html/template, assets embedded, a strict
// Content-Security-Policy (default-src 'none', the inline style and script
// allowed by their SHA-256 only), and the report data embedded as escaped
// JSON. Every value of the report is untrusted text (names and tags come
// from the scanned inputs): html/template escapes it for its context, the
// script never writes markup, and nothing loads from the network.
package htmlreport

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"slices"
	"strings"

	"github.com/r3oof-900/darb/pkg/schema"
)

//go:embed report.html.tmpl report.css report.js
var assets embed.FS

// Reporter writes the HTML report.
type Reporter struct{}

// Severities in report order.
var severities = []string{"critical", "high", "medium", "low", "info"}

type page struct {
	CSP        string
	CSS        template.CSS
	JS         template.JS
	R          *schema.Report
	Data       *schema.Report
	Severities []severityCount
}

type severityCount struct {
	Name  string
	Count int
}

// Write renders r as one HTML document.
func (Reporter) Write(w io.Writer, r *schema.Report) error {
	t, css, js, err := load()
	if err != nil {
		return err
	}
	p := &page{CSS: template.CSS(css), JS: template.JS(js), R: r, Data: r} //nolint:gosec // G203: the embedded assets of this package, not report data
	p.CSP = CSP(css, js)
	for _, s := range severities {
		p.Severities = append(p.Severities, severityCount{s, r.Summary.BySeverity[s]})
	}
	return t.Execute(w, p)
}

// CSP is the policy of a page whose only inline style and script are css
// and js: nothing else may load or run.
func CSP(css, js string) string {
	return "default-src 'none'; style-src " + hash(css) + "; script-src " + hash(js) +
		"; img-src 'none'; base-uri 'none'; form-action 'none'"
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func load() (t *template.Template, css, js string, err error) {
	read := func(name string) (string, error) {
		b, rerr := assets.ReadFile(name)
		return string(b), rerr
	}
	if css, err = read("report.css"); err != nil {
		return nil, "", "", err
	}
	if js, err = read("report.js"); err != nil {
		return nil, "", "", err
	}
	src, err := read("report.html.tmpl")
	if err != nil {
		return nil, "", "", err
	}
	t, err = template.New("report").Funcs(funcs).Parse(src)
	if err != nil {
		return nil, "", "", fmt.Errorf("htmlreport: %w", err)
	}
	return t, css, js, nil
}

var funcs = template.FuncMap{
	"upper": strings.ToUpper,
	"status": func(s string) string {
		switch s {
		case "confirmed_unless_denied":
			return "confirmed unless denied"
		case "unconfirmed":
			return "unconfirmed"
		}
		return ""
	},
	// search: the lower-case text a finding is found by (escaped in its
	// attribute like any other value).
	"search": func(f *schema.Finding) string {
		return strings.ToLower(strings.Join([]string{f.Rule, f.Title, f.Entry, f.Jewel, f.Resource, f.Fingerprint}, " "))
	},
	"pending": func(f *schema.Finding) bool { return f.RemediationStatus == "partial_pending_resolution" },
	"layout":  layout,
	"groups":  groups,
	"plural": func(n int, one, many string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %s", n, many)
	},
	// resolveOnly: the cut is resolve steps only (decide, then rescan).
	"resolveOnly": func(f *schema.Finding) bool {
		for _, s := range f.Fix {
			if s.Kind != "resolve" {
				return false
			}
		}
		return len(f.Fix) > 0
	},
	"first": func(fs []schema.Fix) *schema.Fix {
		if len(fs) == 0 {
			return nil
		}
		return &fs[0]
	},
	"rest": func(fs []schema.Fix) []schema.Fix {
		if len(fs) < 2 {
			return nil
		}
		return fs[1:]
	},
	// difflines: a unified diff's lines, each with its class (add, del,
	// hunk, file, ctx) for the CSS; the text stays text.
	"difflines": difflines,
	// unfixed: some path finding has a cut but no verified fix in the report.
	"unfixed": func(r *schema.Report) bool {
		for i := range r.Findings {
			if f := &r.Findings[i]; len(f.Chokepoints) > 0 && f.Remediation == nil {
				return true
			}
		}
		return false
	},
	"refs":  deref[schema.FindingRef],
	"uncut": deref[schema.UncuttableEdge],
}

func deref[T any](p *[]T) []T {
	if p == nil {
		return nil
	}
	return *p
}

type diffLine struct{ Class, Text string }

func difflines(diff string) []diffLine {
	lines := strings.Split(strings.TrimSuffix(diff, "\n"), "\n")
	out := make([]diffLine, 0, len(lines))
	for _, l := range lines {
		c := "ctx"
		switch {
		case strings.HasPrefix(l, "+++"), strings.HasPrefix(l, "---"):
			c = "file"
		case strings.HasPrefix(l, "@@"):
			c = "hunk"
		case strings.HasPrefix(l, "+"):
			c = "add"
		case strings.HasPrefix(l, "-"):
			c = "del"
		}
		out = append(out, diffLine{c, l})
	}
	return out
}

// findingGroups: the attack paths (path rules) and the misconfigurations
// (posture rules), each by severity, then score, then as reported.
type findingGroups struct {
	Paths, Posture []*schema.Finding
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func groups(r *schema.Report) findingGroups {
	var g findingGroups
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.Kind == "path" {
			g.Paths = append(g.Paths, f)
		} else {
			g.Posture = append(g.Posture, f)
		}
	}
	order := func(a, b *schema.Finding) int {
		if d := severityRank[a.Severity] - severityRank[b.Severity]; d != 0 {
			return d
		}
		return b.Score - a.Score
	}
	slices.SortStableFunc(g.Paths, order)
	slices.SortStableFunc(g.Posture, order)
	return g
}
