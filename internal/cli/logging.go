package cli

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/r3oof-900/darb/internal/app"
	"github.com/r3oof-900/darb/internal/redact"
	"github.com/r3oof-900/darb/pkg/schema"
)

// globals are the flags every command takes, anywhere before "--":
// --log-format text|json and --debug (DESIGN.md §11, logging).
type globals struct {
	logFormat string
	debug     bool
}

var errLogFormat = errors.New("--log-format is text or json")

// splitGlobals removes the global flags from args and returns the rest.
func splitGlobals(args []string) ([]string, globals, error) {
	g := globals{logFormat: "text"}
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return append(rest, args[i:]...), g, nil
		case a == "--debug" || a == "-debug":
			g.debug = true
		case a == "--log-format" || a == "-log-format":
			next := args[i+1:]
			if len(next) == 0 {
				return nil, g, errLogFormat
			}
			g.logFormat = next[0]
			i++
		case strings.HasPrefix(a, "--log-format=") || strings.HasPrefix(a, "-log-format="):
			_, g.logFormat, _ = strings.Cut(a, "=")
		default:
			rest = append(rest, a)
		}
	}
	if !slices.Contains([]string{"text", "json"}, g.logFormat) {
		return nil, g, errLogFormat
	}
	return rest, g, nil
}

// newLogger writes slog records to w, every one through the redacting
// handler: the message and every attribute, in text or JSON. Without
// --debug only warnings are written; with it, info and debug records too.
func newLogger(w io.Writer, g globals) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelWarn}
	if g.debug {
		opts.Level = slog.LevelDebug
	}
	var h slog.Handler = slog.NewTextHandler(w, opts)
	if g.logFormat == "json" {
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(redact.NewHandler(h))
}

// Debug reports whether the command line asks for --debug (main uses it
// for the stack trace of a recovered panic).
func Debug(args []string) bool {
	_, g, _ := splitGlobals(args)
	return g.debug
}

// Crash reports a recovered panic: one line, and with --debug the stack
// trace, both redacted.
func Crash(w io.Writer, args []string, r any) {
	w = redacting{w}
	_, _ = fmt.Fprintf(w, "darb: internal error: %v (a bug: please report it with the command line; see SECURITY.md for a security issue)\n", r)
	if Debug(args) {
		_, _ = w.Write(debug.Stack())
		return
	}
	_, _ = fmt.Fprintln(w, "darb: run again with --debug for the stack trace")
}

// logLoaded: what was read (debug) and every coverage gap (debug; their
// count beyond tolerance is a warning once analysed).
func logLoaded(log *slog.Logger, f *scanFlags, l *app.Loaded) {
	log.Debug("inputs loaded", "root", f.root, "collected", l.Collected, "gaps", len(l.Gaps))
	for i := range l.Gaps {
		g := &l.Gaps[i]
		log.Debug("coverage gap", "kind", string(g.Kind), "source", g.Source, "file", g.File, "line", g.Line,
			"address", g.Address, "account", g.Account, "api", g.API, "detail", g.Detail)
	}
	if f.k8s.insecure {
		log.Warn("TLS verification is off for the live clusters (--insecure)")
	}
}

func logAnalysis(log *slog.Logger, a *app.Analysis, took time.Duration) {
	log.Info("analysis", "nodes", a.Graph.Nodes, "edges", a.Graph.Edges, "pairs", a.Graph.Pairs,
		"findings", len(a.Findings), "gaps_over_tolerance", a.GapsCounted, "duration_ms", took.Milliseconds())
	if a.GapsCounted > 0 {
		log.Warn("coverage gaps beyond tolerance: the scan is incomplete", "count", a.GapsCounted)
	}
}

// logReport: an LLM explanation that fell back to the template is a
// warning (the report says so too).
func logReport(log *slog.Logger, r *schema.Report) {
	for i := range r.Findings {
		if e := r.Findings[i].Explanation; e != nil && !e.AIGenerated && strings.HasPrefix(e.Note, "the LLM explanation failed") {
			log.Warn("LLM explanation fell back to the template", "fingerprint", r.Findings[i].Fingerprint, "reason", e.Note)
		}
	}
	log.Debug("report", "findings", len(r.Findings), "exit_code", r.ExitCode)
}
