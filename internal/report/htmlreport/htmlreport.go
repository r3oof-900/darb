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
	"strings"

	"github.com/r3oof-900/clapa/pkg/schema"
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
	"refs":    deref[schema.FindingRef],
	"uncut":   deref[schema.UncuttableEdge],
}

func deref[T any](p *[]T) []T {
	if p == nil {
		return nil
	}
	return *p
}
