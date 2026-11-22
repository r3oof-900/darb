package app

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/r3oof-900/darb/internal/patch"
	"github.com/r3oof-900/darb/internal/remediate"
	"github.com/r3oof-900/darb/internal/verify"
)

// WriteRemediation prints a remediation: the finding, what is missing (an
// UNKNOWN path), then each fix in order — its strategy, each change with
// its side, kind and cost, both verifications, the patch and JSON
// policies — and the advice when the root cause is not verified.
func WriteRemediation(w io.Writer, r *Remediation) {
	p := func(a ...any) { _, _ = fmt.Fprintln(w, a...) }
	f := r.Finding
	p("finding", f.Fingerprint, f.Rule, f.Entry+f.Resource, "->", f.Jewel)
	for _, s := range r.Plan.Pending {
		p("resolve first (no change):", s)
	}
	if len(r.Plan.Pending) > 0 {
		p(verify.PendingNote)
	}
	if len(r.Plan.Missing) > 0 && len(r.Plan.Changes) == 0 {
		p("UNKNOWN: no patch until the path is decided. What would decide it:")
		for _, m := range r.Plan.Missing {
			p("  -", m)
		}
		return
	}
	if len(r.Plan.Changes) == 0 && len(r.Plan.Pending) > 0 {
		return
	}
	if r.Plan.NoFix {
		p("no fix within the constraints (intended access, uncuttable edges)")
		return
	}
	for i, fix := range append([]*Remediation{r}, r.Others...) {
		if i > 0 {
			p()
		}
		writeFix(w, fix)
	}
	if r.Note != "" {
		p()
		p(r.Note)
	}
}

// Strategy is how a fix is labelled.
func Strategy(r *Remediation) string {
	switch {
	case r.Plan.Strategy == remediate.StrategyMitigation:
		return "mitigation: blocks this path only; the broad grant remains"
	case r.Plan.Suggestion != "":
		return "root-cause fix: a suggestion, not verified, not applied by --write"
	}
	return "root-cause fix"
}

func writeFix(w io.Writer, r *Remediation) {
	p := func(a ...any) { _, _ = fmt.Fprintln(w, a...) }
	p("==", Strategy(r))
	if r.Plan.Suggestion != "" {
		p("  " + r.Plan.Suggestion)
		return
	}
	for i := range r.Plan.Changes {
		c := &r.Plan.Changes[i]
		p(fmt.Sprintf("change: %s", c.Edge))
		p(fmt.Sprintf("  %s side, %s, cost %d: %s", c.Side, c.Kind, c.Cost, c.Why))
		if c.Kind == "revoke" {
			p("  this removes an explicit grant; confirm it is not needed")
		}
		if c.TODO != "" {
			p("  TODO:", c.TODO)
		}
	}
	p("verified in memory:", verdict(r.Memory.OK, r.Memory.Reasons))
	p("verified on the patched files (rescanned from scratch):", verdict(r.Files.OK, r.Files.Reasons))
	if r.Patch == nil {
		return
	}
	for _, t := range r.Patch.TODO {
		p("TODO:", t)
	}
	if d := r.Patch.Diff(); d != "" {
		p("patch:")
		_, _ = io.WriteString(w, d)
	}
	for _, pol := range r.Patch.Policies {
		p("policy", pol.ID+":", pol.Note)
		if pol.Document != "" {
			p(pol.Document)
		}
	}
}

func verdict(ok bool, reasons []string) string {
	if ok {
		return "yes"
	}
	return "no: " + strings.Join(reasons, "; ")
}

// WritePatch writes the patched files into the scan root, keeping each
// file's permissions; it returns the paths written.
func WritePatch(root string, res *patch.Result) ([]string, error) {
	var out []string
	for _, f := range res.Files {
		file := filepath.Join(root, filepath.FromSlash(f.Path))
		info, err := os.Stat(file)
		if err != nil {
			return out, err
		}
		cur, err := os.ReadFile(file) //nolint:gosec // G304: a file of the scanned inputs.
		if err != nil {
			return out, err
		}
		if !bytes.Equal(cur, f.Before) {
			return out, fmt.Errorf("%s changed since it was scanned; not written", f.Path)
		}
		if err := os.WriteFile(file, f.After, info.Mode().Perm()); err != nil {
			return out, err
		}
		out = append(out, f.Path)
	}
	return out, nil
}
