package app

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/r3oof-900/clapa/internal/patch"
)

// WriteRemediation prints a remediation: the finding, what is missing (an
// UNKNOWN path), each change with its side, kind and cost, both
// verifications, the patch and the JSON policies.
func WriteRemediation(w io.Writer, r *Remediation) {
	p := func(a ...any) { _, _ = fmt.Fprintln(w, a...) }
	f := r.Finding
	p("finding", f.Fingerprint, f.Rule, f.Entry+f.Resource, "->", f.Jewel)
	if len(r.Plan.Missing) > 0 {
		p("UNKNOWN: no patch until the path is decided. What would decide it:")
		for _, m := range r.Plan.Missing {
			p("  -", m)
		}
		return
	}
	if r.Plan.NoFix {
		p("no fix within the constraints (intended access, uncuttable edges)")
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
