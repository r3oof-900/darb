package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/classify"
	"github.com/r3oof-900/clapa/internal/config"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/patch"
	"github.com/r3oof-900/clapa/internal/remediate"
	"github.com/r3oof-900/clapa/internal/rules"
	"github.com/r3oof-900/clapa/internal/safeio"
	"github.com/r3oof-900/clapa/internal/verify"
)

// Remediation is the verified remediation of one finding (DESIGN.md §9).
type Remediation struct {
	Finding *rules.Finding
	Plan    *remediate.Plan
	// Memory is the level-1 verification (the model), Files the level-2
	// one (the patch rescanned from scratch); a fix is accepted only when
	// both are OK.
	Memory verify.Outcome
	Files  verify.Outcome
	Patch  *patch.Result
}

// Accepted reports whether the fix is verified on both levels.
func (r *Remediation) Accepted() bool { return r.Memory.OK && r.Files.OK }

// resultOf is what verification compares of an analysis.
func resultOf(a *Analysis) *verify.Result {
	r := &verify.Result{Findings: map[string]string{}, Intended: map[string]string{}, ExitCode: a.ExitCode}
	for i := range a.Findings {
		r.Findings[a.Findings[i].Fingerprint] = a.Findings[i].Factors.Severity
	}
	for _, ia := range a.IntendedAccess {
		r.Intended[ia.Principal+" "+ia.Action+" "+ia.Resource] = ia.Status
	}
	return r
}

// findFinding: the finding with a fingerprint (or a unique prefix of one).
func findFinding(a *Analysis, fp string) (*rules.Finding, error) {
	var found *rules.Finding
	for i := range a.Findings {
		if strings.HasPrefix(a.Findings[i].Fingerprint, fp) {
			if found != nil {
				return nil, fmt.Errorf("fingerprint prefix %q matches more than one finding", fp)
			}
			found = &a.Findings[i]
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no finding has fingerprint %q", fp)
	}
	return found, nil
}

// analyzer re-runs the analysis on a changed inventory (level 1): the same
// gaps and inputs, the entry points of the new inventory.
func analyzer(l *Loaded, cfg *config.Config, failOn string) verify.Analyzer {
	return func(inv *model.Inventory) (*verify.Result, error) {
		changed := *l
		changed.Inventory = inv
		changed.EntryPoints = classify.EntryPoints(inv, *cfg.ThreatModel.AssumeCompromised)
		a, err := Analyze(&changed, cfg, failOn)
		if err != nil {
			return nil, err
		}
		return resultOf(a), nil
	}
}

// PlanFix plans and verifies in memory the remediation of the finding with
// fingerprint fp (level 1 only; Remediate adds the patch and level 2).
func PlanFix(l *Loaded, cfg *config.Config, a *Analysis, fp string) (*Remediation, error) {
	f, err := findFinding(a, fp)
	if err != nil {
		return nil, err
	}
	plan := remediate.ForFinding(&remediate.Input{Inventory: l.Inventory, Graph: a.AccessGraph}, f)
	r := &Remediation{Finding: f, Plan: plan}
	switch {
	case len(plan.Missing) > 0:
		r.Memory = verify.Outcome{Reasons: []string{"the finding is not confirmed: no patch until it is decided"}}
	case plan.NoFix:
		r.Memory = verify.Outcome{Reasons: []string{"no fix within the constraints (intended access, uncuttable edges)"}}
	default:
		r.Memory = verify.InMemory(l.Inventory, resultOf(a), plan, analyzer(l, cfg, DefaultFailOn))
	}
	return r, nil
}

// Remediate plans, patches and verifies on both levels the remediation of
// the finding with fingerprint fp: in memory (the model), then the patch on
// a copy of the inputs rescanned from scratch, whose result must be the
// in-memory one exactly (DESIGN.md §9.2).
func Remediate(ctx context.Context, in *Inputs, l *Loaded, a *Analysis, fp string) (*Remediation, error) {
	r, err := PlanFix(l, in.Config, a, fp)
	if err != nil {
		return nil, err
	}
	return r, finishFix(ctx, in, l, r)
}

// verifyPlan verifies a given plan for a finding on both levels (the plan
// need not be the generated one: a test can check any candidate).
func verifyPlan(ctx context.Context, in *Inputs, l *Loaded, a *Analysis, plan *remediate.Plan) (*Remediation, error) {
	f, err := findFinding(a, plan.Fingerprint)
	if err != nil {
		return nil, err
	}
	r := &Remediation{Finding: f, Plan: plan}
	r.Memory = verify.InMemory(l.Inventory, resultOf(a), plan, analyzer(l, in.Config, DefaultFailOn))
	return r, finishFix(ctx, in, l, r)
}

// finishFix renders the patch of a plan verified in memory and runs level 2.
func finishFix(ctx context.Context, in *Inputs, l *Loaded, r *Remediation) error {
	if !r.Memory.OK {
		r.Files = verify.Outcome{Reasons: []string{"not run: the in-memory verification did not pass"}}
		return nil
	}
	var edits []remediate.Edit
	for i := range r.Plan.Changes {
		edits = append(edits, r.Plan.Changes[i].Edits...)
	}
	configs := slices.Clone(in.TerraformDirs)
	for _, p := range in.TerraformPlans {
		if p.ConfigDir != "" {
			configs = append(configs, p.ConfigDir)
		}
	}
	var err error
	r.Patch, err = patch.Render(l.Inventory, edits, &rootSource{in: in}, &patch.Options{Snapshots: in.AWSSnapshots, ConfigDirs: configs})
	if err != nil {
		return err
	}
	r.Files = rescan(ctx, in, r)
	return nil
}

// rescan is level 2: the inputs are copied to a temporary directory outside
// the scan root, the patch is applied there, and the scan runs again from
// parsing on.
func rescan(ctx context.Context, in *Inputs, r *Remediation) verify.Outcome {
	switch {
	case !r.Patch.Complete():
		return verify.Outcome{Reasons: append([]string{"the patch is incomplete (TODO)"}, r.Patch.TODO...)}
	case len(in.TerraformPlans) > 0 && slices.ContainsFunc(r.Patch.Files, func(f patch.FileChange) bool { return strings.HasSuffix(f.Path, ".tf") }):
		return verify.Outcome{Reasons: []string{"the scan reads a Terraform plan: the patched configuration needs a new plan (terraform plan) before it can be rescanned"}}
	}
	dir, err := os.MkdirTemp("", "clapa-verify-*")
	if err != nil {
		return verify.Outcome{Reasons: []string{err.Error()}}
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if cerr := copyInputs(in, dir); cerr != nil {
		return verify.Outcome{Reasons: []string{"copying the inputs: " + cerr.Error()}}
	}
	for _, f := range slices.Concat(r.Patch.Files, r.Patch.Snapshot) {
		if werr := os.WriteFile(filepath.Join(dir, filepath.FromSlash(f.Path)), f.After, 0o600); werr != nil {
			return verify.Outcome{Reasons: []string{werr.Error()}}
		}
	}
	copied := *in
	copied.Root = dir
	l, err := Load(ctx, &copied)
	if err != nil {
		return verify.Outcome{Reasons: []string{"rescan: " + err.Error()}}
	}
	a, err := Analyze(l, in.Config, DefaultFailOn)
	if err != nil {
		return verify.Outcome{Reasons: []string{"rescan: " + err.Error()}}
	}
	files := resultOf(a)
	reasons := verify.Same(r.Memory.After, files)
	return verify.Outcome{OK: len(reasons) == 0, Reasons: reasons, After: files}
}

// copyInputs copies the scanned inputs (and only them) to dir, keeping
// their paths relative to the root.
func copyInputs(in *Inputs, dir string) error {
	for _, p := range inputPaths(in) {
		err := filepath.WalkDir(filepath.Join(in.Root, filepath.FromSlash(p)), func(file string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			return copyEntry(in.Root, dir, file, d)
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

func inputPaths(in *Inputs) []string {
	var paths []string
	for _, p := range in.TerraformPlans {
		paths = append(paths, p.Path)
		if p.ConfigDir != "" {
			paths = append(paths, p.ConfigDir)
		}
	}
	paths = append(paths, in.TerraformDirs...)
	for _, k := range in.K8sDirs {
		paths = append(paths, k.Path)
	}
	return append(paths, in.AWSSnapshots...)
}

// copyEntry copies one walked entry of root into dir.
func copyEntry(root, dir, file string, d fs.DirEntry) error {
	rel, err := filepath.Rel(root, file)
	if err != nil {
		return err
	}
	target := filepath.Join(dir, rel)
	if d.IsDir() {
		return os.MkdirAll(target, 0o750)
	}
	if !d.Type().IsRegular() {
		return nil // symlinks and devices are not inputs (safeio refuses them)
	}
	data, err := os.ReadFile(file) //nolint:gosec // G304: a file of the scanned inputs.
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return err
	}
	return os.WriteFile(target, data, 0o600) //nolint:gosec // G703: inside our own temp dir.
}

// rootSource reads the scan's files for the patcher.
type rootSource struct{ in *Inputs }

func (s *rootSource) Read(p string) ([]byte, error) {
	return safeio.ReadFile(s.in.Root, path.Clean(p), s.in.Limits)
}

func (s *rootSource) List(dir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.in.Root, filepath.FromSlash(dir)))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			out = append(out, path.Join(dir, e.Name()))
		}
	}
	return out, nil
}

func (s *rootSource) Walk(dir string) ([]string, error) {
	base := filepath.Join(s.in.Root, filepath.FromSlash(dir))
	var out []string
	err := filepath.WalkDir(base, func(file string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, err := filepath.Rel(s.in.Root, file)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out, err
}
