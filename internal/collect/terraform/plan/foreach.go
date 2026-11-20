package plan

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	tfjson "github.com/hashicorp/terraform-json"

	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/safeio"
)

// A plan cannot say whether a for_each source is a set: toset(var.names) and
// { for n in var.names : n => upper(n) } are both recorded as
// for_each_expression {"references": ["var.names"]} with the same instance
// keys (checked with Terraform 1.17.1). For a set, each.value is each.key
// (Terraform › "The for_each Meta-Argument": "If a set was provided, this is
// the same as each.key"); for a map it is the map value. So the set is
// verified in the configuration the plan was made from, when it is given:
// the for_each expression is toset(...), or a variable declared with a
// set(...) type. Nothing is evaluated; only local module sources are
// followed, through safeio, inside the scan root.

type forEachKind uint8

const (
	forEachUnverified forEachKind = iota // not a provable set
	forEachSet
)

type configSource struct {
	root    string // scan root
	limits  safeio.Limits
	dirs    map[string]string // module path ("" root, "module.a") -> dir relative to root; "" when not local
	why     map[string]string // module path -> why its dir is unknown
	modules map[string]*moduleConfig
	rec     *coverage.Recorder
}

type moduleConfig struct {
	forEach   map[string]hclsyntax.Expression // "type.name" -> for_each expression
	variables map[string]hclsyntax.Expression // name -> type expression
}

// newConfigSource maps every module of the plan to its local directory.
func newConfigSource(root, dir string, limits safeio.Limits, cfg *tfjson.Config, rec *coverage.Recorder) *configSource {
	s := &configSource{
		root: root, limits: limits, rec: rec,
		dirs: map[string]string{}, why: map[string]string{}, modules: map[string]*moduleConfig{},
	}
	if cfg != nil {
		s.mapModules("", path.Clean(dir), cfg.RootModule)
	}
	return s
}

func (s *configSource) mapModules(prefix, dir string, m *tfjson.ConfigModule) {
	s.dirs[prefix] = dir
	if m == nil {
		return
	}
	for _, name := range sortedKeys(m.ModuleCalls) {
		call := m.ModuleCalls[name]
		child := join(prefix, "module."+name)
		switch {
		case dir == "":
			s.why[child] = s.why[prefix]
			s.mapModules(child, "", call.Module)
		case strings.HasPrefix(call.Source, "./") || strings.HasPrefix(call.Source, "../"):
			s.mapModules(child, path.Join(dir, call.Source), call.Module)
		default:
			s.why[child] = "module source " + call.Source + " is not a local directory"
			s.mapModules(child, "", call.Module)
		}
	}
}

// kind classifies the for_each of resource typ.name in module, and says why
// a source that is not a provable set could not be verified.
func (s *configSource) kind(module, typ, name string) (kind forEachKind, why string) {
	dir, mapped := s.dirs[module]
	if !mapped || dir == "" {
		if w := s.why[module]; w != "" {
			return forEachUnverified, w
		}
		return forEachUnverified, "the configuration of " + module + " is not in the plan"
	}
	mc := s.load(dir)
	expr, ok := mc.forEach[typ+"."+name]
	if !ok {
		return forEachUnverified, "for_each of " + typ + "." + name + " is not in " + dir
	}
	switch x := expr.(type) {
	case *hclsyntax.FunctionCallExpr:
		if x.Name == "toset" {
			return forEachSet, ""
		}
	case *hclsyntax.ScopeTraversalExpr:
		if t := x.Traversal; len(t) == 2 && t.RootName() == "var" {
			if attr, ok := t[1].(hcl.TraverseAttr); ok {
				if ty, ok := mc.variables[attr.Name].(*hclsyntax.FunctionCallExpr); ok && ty.Name == "set" {
					return forEachSet, ""
				}
			}
		}
	}
	return forEachUnverified, "for_each of " + typ + "." + name + " is not toset(...) or a set-typed variable (a map's each.value is not its key)"
}

// load parses the .tf files of one module directory (not its subdirectories).
func (s *configSource) load(dir string) *moduleConfig {
	if mc, ok := s.modules[dir]; ok {
		return mc
	}
	mc := &moduleConfig{forEach: map[string]hclsyntax.Expression{}, variables: map[string]hclsyntax.Expression{}}
	s.modules[dir] = mc
	if dir == ".." || strings.HasPrefix(dir, "../") || path.IsAbs(dir) {
		s.rec.Add(&coverage.Gap{Kind: coverage.KindUnsupported, Source: Name, File: dir, Detail: "module directory is outside the scan root; not read"})
		return mc
	}
	files, err := safeio.Walk(joinRoot(s.root, dir), []string{".tf"})
	if err != nil {
		s.rec.Add(&coverage.Gap{Kind: coverage.KindParseError, Source: Name, File: dir, Detail: err.Error()})
		return mc
	}
	for _, f := range files {
		if strings.Contains(f, "/") {
			continue // a subdirectory is another module
		}
		s.parse(path.Join(dir, f), mc)
	}
	return mc
}

func (s *configSource) parse(file string, mc *moduleConfig) {
	data, err := safeio.ReadFile(s.root, file, s.limits)
	if err != nil {
		s.rec.Add(&coverage.Gap{Kind: coverage.KindParseError, Source: Name, File: file, Detail: err.Error()})
		return
	}
	f, diags := hclsyntax.ParseConfig(data, file, hcl.InitialPos)
	if diags.HasErrors() {
		s.rec.Add(&coverage.Gap{Kind: coverage.KindParseError, Source: Name, File: file, Detail: diags.Error()})
		return
	}
	body, _ := f.Body.(*hclsyntax.Body) // ParseConfig always returns *hclsyntax.Body
	for _, b := range body.Blocks {
		switch {
		case b.Type == "resource" && len(b.Labels) == 2:
			if a, ok := b.Body.Attributes["for_each"]; ok {
				mc.forEach[b.Labels[0]+"."+b.Labels[1]] = a.Expr
			}
		case b.Type == "variable" && len(b.Labels) == 1:
			if a, ok := b.Body.Attributes["type"]; ok {
				mc.variables[b.Labels[0]] = a.Expr
			}
		}
	}
}

func joinRoot(root, dir string) string { return filepath.Join(root, filepath.FromSlash(dir)) }
