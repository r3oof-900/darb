package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/app"
	"github.com/r3oof-900/darb/pkg/schema"
)

// llmFlags are the explanation flags of scan and explain (DESIGN.md §10).
// The API key is read from the environment only: never a flag (it would be
// in the shell history and the process list), never printed.
type llmFlags struct {
	provider, model string
	redactIDs       bool
}

func (l *llmFlags) on(fs *flag.FlagSet) {
	fs.StringVar(&l.provider, "llm", "", "explain findings in plain words with this LLM provider ("+strings.Join(app.LLMProviders(), ", ")+"; key in "+app.LLMKeyVariable+"); off by default")
	fs.StringVar(&l.model, "llm-model", "", "with --llm: the model (default claude-opus-5-5)")
	fs.BoolVar(&l.redactIDs, "llm-redact-identifiers", false, "with --llm: send account IDs, ARNs and names as tokens, put back locally")
}

func (l *llmFlags) check() error {
	if l.provider == "" && (l.model != "" || l.redactIDs) {
		return errors.New("--llm-model and --llm-redact-identifiers need --llm")
	}
	return nil
}

// explainer makes the provider of the flags.
func (l *llmFlags) explainer(env *Env) (app.Explainer, app.LLMOptions, error) {
	if err := l.check(); err != nil {
		return nil, app.LLMOptions{}, err
	}
	o := app.LLMOptions{Provider: l.provider, Model: l.model, RedactIdentifiers: l.redactIDs}
	if l.provider != "" {
		o.APIKey = env.getenv(app.LLMKeyVariable)
	}
	p, err := env.explainer(o)
	return p, o, err
}

// explainCmd: `darb explain [scan input flags] [--llm P [--llm-model M]
// [--llm-redact-identifiers]] FINGERPRINT` prints one finding in plain
// words. Without --llm it prints the template text. It runs on files and
// snapshots, like remediate. Exit codes: 0 explained (by the provider or,
// when it failed, by the template, with a note); 2 usage; 3 incomplete
// input; 4 internal.
func explainCmd(ctx context.Context, args []string, stdout, stderr io.Writer, env *Env) ExitCode {
	f := &scanFlags{}
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	scanFlagsOn(fs, f)
	f.llm.on(fs)
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		if err == nil {
			_, _ = fmt.Fprintln(stderr, "darb: explain needs exactly one finding fingerprint (or a unique prefix of one)")
		}
		return ExitUsage
	}
	if unused(fs, "explain", stderr, "output", "ignore", "baseline") {
		return ExitUsage
	}
	if !slices.Contains([]string{"console", "json"}, f.format) || f.aws.live || f.k8s.any() {
		_, _ = fmt.Fprintln(stderr, "darb: explain prints console or json, and reads files and snapshots (collect-snapshot first for live data)")
		return ExitUsage
	}
	p, opts, err := f.llm.explainer(env)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "darb:", err)
		return ExitUsage
	}
	a, cfg, code := analyzeInputs(ctx, f, env, stderr, false)
	if a == nil {
		return code
	}
	found, err := app.ExplainFinding(ctx, app.Report(a, cfg, f.failOn), fs.Arg(0), p, opts.RedactIdentifiers)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "darb:", err)
		return ExitUsage
	}
	if f.format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(found.Explanation); err != nil {
			return ExitInternal
		}
		return ExitOK
	}
	printExplanation(stdout, found)
	return ExitOK
}

func printExplanation(w io.Writer, f *schema.Finding) {
	e := f.Explanation
	_, _ = fmt.Fprintf(w, "[%s %d] %s  %s\nfingerprint %s\n\n%s\n\n%s\n", strings.ToUpper(f.Severity), f.Score, f.Rule, f.Title, f.Fingerprint, e.Label(), e.Summary)
	if e.Attack != "" {
		_, _ = fmt.Fprintf(w, "\nThe attack: %s\n", e.Attack)
	}
	if e.Fix != "" {
		_, _ = fmt.Fprintf(w, "\nThe fix: %s\n", e.Fix)
	}
}
