package app

import (
	"errors"
	"fmt"
	"io"

	"github.com/r3oof-900/clapa/internal/config"
	"github.com/r3oof-900/clapa/internal/report"
	"github.com/r3oof-900/clapa/internal/report/console"
	"github.com/r3oof-900/clapa/internal/report/htmlreport"
	"github.com/r3oof-900/clapa/internal/report/jsonreport"
	"github.com/r3oof-900/clapa/internal/report/sarif"
	"github.com/r3oof-900/clapa/pkg/schema"
)

// ErrFormat is returned for an output format that does not exist.
var ErrFormat = errors.New("app: unknown output format")

// Formats are the output formats of "clapa scan --format".
func Formats() []string { return []string{"console", "json", "sarif", "html"} }

// Report builds the versioned report document of an analysis.
func Report(a *Analysis, cfg *config.Config, failOn string) *schema.Report {
	in := &report.Input{
		Findings: a.Findings, Registry: a.Registry, CatalogVersion: a.CatalogVersion,
		Gaps: a.Gaps, Collected: a.Collected, GapsOverTolerance: a.GapsCounted, ExitCode: a.ExitCode,
		Graph:             schema.Graph{Nodes: a.Graph.Nodes, Edges: a.Graph.Edges, Pairs: a.Graph.Pairs},
		AssumeCompromised: *cfg.ThreatModel.AssumeCompromised, FailOn: failOn,
	}
	for _, ia := range a.IntendedAccess {
		in.IntendedAccess = append(in.IntendedAccess, schema.IntendedAccess{
			Principal: ia.Principal, Action: ia.Action, Resource: ia.Resource, Status: ia.Status, Detail: ia.Detail,
		})
	}
	for _, n := range a.Notes {
		in.Notes = append(in.Notes, schema.Note{Kind: n.Kind, Subject: n.Subject, Detail: n.Detail})
	}
	r := report.Build(in)
	r.Suppressed, r.ExpiredSuppressions, r.Baseline = a.Suppressed, a.Expired, a.Baseline
	r.Inputs = a.Inputs
	return r
}

// Write renders a report in a format.
func Write(w io.Writer, format string, r *schema.Report) error {
	var rep report.Reporter
	switch format {
	case "console":
		rep = console.Reporter{}
	case "json":
		rep = jsonreport.Reporter{}
	case "sarif":
		rep = sarif.Reporter{}
	case "html":
		rep = htmlreport.Reporter{}
	default:
		return fmt.Errorf("%w %q (one of %v)", ErrFormat, format, Formats())
	}
	return rep.Write(w, r)
}
