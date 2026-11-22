package hclstatic

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/r3oof-900/darb/internal/collect"
	"github.com/r3oof-900/darb/internal/collect/tfraw"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/safeio"
)

// Name identifies this collector in coverage gaps.
const Name = "terraform-hcl"

// Collect parses every directory with .tf files under in.Path as a root
// module, evaluated without a plan (docs/DESIGN.md section 4.1). Module calls
// and count/for_each are not expanded; they are reported as unresolved.
// A file that does not parse is reported with file:line and skipped; the
// rest of the scan continues.
func Collect(ctx context.Context, in *collect.Input, rec *coverage.Recorder) (*tfraw.Module, error) {
	base := filepath.Join(in.Root, filepath.FromSlash(in.Path))
	files, err := safeio.Walk(base, []string{".tf", ".tfvars"})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	m := &tfraw.Module{Source: "hcl"}
	for _, dir := range dirs(files) {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		mod := &rootModule{
			root: base, inPath: in.Path, prefix: path.Join(in.Path, dir),
			rec: rec, limits: in.Limits, src: map[string][]byte{},
		}
		mod.load(filesIn(files, dir))
		mod.evaluate()
		m.Resources = append(m.Resources, mod.resources()...)
		m.Providers = append(m.Providers, mod.providers()...)
	}
	m.Sort()
	return m, nil
}

// dirs returns the directories that contain .tf files, sorted.
func dirs(files []string) []string {
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f, ".tf") && !slices.Contains(out, path.Dir(f)) {
			out = append(out, path.Dir(f))
		}
	}
	slices.Sort(out)
	return out
}

func filesIn(files []string, dir string) []string {
	var out []string
	for _, f := range files {
		if path.Dir(f) == dir {
			out = append(out, f)
		}
	}
	return out
}

// rootModule is one directory evaluated as a Terraform root module.
type rootModule struct {
	root   string // filesystem path that Walk ran on
	inPath string // the input path, relative to the scan root (for display)
	prefix string // this module's directory, relative to the scan root
	rec    *coverage.Recorder
	limits safeio.Limits
	src    map[string][]byte // file -> source, for expression text
	vars   map[string]*hclsyntax.Attribute
	tfvars []*hclsyntax.Attribute
	locals map[string]*hclsyntax.Attribute
	blocks []*hclsyntax.Block // resource, data, provider
	ctx    *hcl.EvalContext
}

func (m *rootModule) load(files []string) {
	m.vars, m.locals = map[string]*hclsyntax.Attribute{}, map[string]*hclsyntax.Attribute{}
	for _, f := range files {
		body, ok := m.parse(f)
		if !ok {
			continue
		}
		if strings.HasSuffix(f, ".tfvars") {
			if isAutoTFVars(f) {
				m.tfvars = append(m.tfvars, sortedAttrs(body.Attributes)...)
			}
			continue
		}
		m.loadBody(body)
	}
}

// isAutoTFVars: Terraform loads terraform.tfvars and *.auto.tfvars automatically.
func isAutoTFVars(f string) bool {
	b := path.Base(f)
	return b == "terraform.tfvars" || strings.HasSuffix(b, ".auto.tfvars")
}

// parse reads and parses f (relative to m.root). Positions and gaps use the
// path relative to the scan root.
func (m *rootModule) parse(f string) (*hclsyntax.Body, bool) {
	name := path.Join(m.inPath, f)
	src, err := safeio.ReadFile(m.root, f, m.limits)
	if err != nil {
		m.gap(coverage.KindParseError, name, 0, "", err.Error())
		return nil, false
	}
	file, diags := hclsyntax.ParseConfig(src, name, hcl.InitialPos)
	for _, d := range diags {
		if d.Severity == hcl.DiagError {
			m.gap(coverage.KindParseError, name, d.Subject.Start.Line, "", d.Summary+": "+d.Detail)
			return nil, false
		}
	}
	body, _ := file.Body.(*hclsyntax.Body) // hclsyntax.ParseConfig always returns *hclsyntax.Body
	m.src[name] = src
	return body, true
}

func (m *rootModule) loadBody(body *hclsyntax.Body) {
	for _, b := range body.Blocks {
		switch b.Type {
		case "variable":
			if len(b.Labels) == 1 {
				m.vars[b.Labels[0]] = b.Body.Attributes["default"]
			}
		case "locals":
			for name, a := range b.Body.Attributes {
				m.locals[name] = a
			}
		case "resource", "data", "provider":
			m.blocks = append(m.blocks, b)
		case "module":
			m.gap(coverage.KindUnresolved, b.TypeRange.Filename, b.TypeRange.Start.Line, "module."+strings.Join(b.Labels, "."),
				"module calls are expanded only from a plan (terraform show -json)")
		}
	}
}

func (m *rootModule) gap(kind coverage.Kind, file string, line int, address, detail string) {
	m.rec.Add(&coverage.Gap{Kind: kind, Source: Name, File: file, Line: line, Address: address, Detail: detail})
}

func sortedAttrs(attrs hclsyntax.Attributes) []*hclsyntax.Attribute {
	out := make([]*hclsyntax.Attribute, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b *hclsyntax.Attribute) int { return strings.Compare(a.Name, b.Name) })
	return out
}
