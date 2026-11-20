package archtest

import (
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Violation is one import or file that breaks the layer table.
type Violation struct {
	File   string // module-relative, slash-separated
	Line   int
	Import string
	Reason string
}

func (v Violation) String() string {
	if v.Import == "" {
		return fmt.Sprintf("%s:%d: %s", v.File, v.Line, v.Reason)
	}
	return fmt.Sprintf("%s:%d: import %q: %s", v.File, v.Line, v.Import, v.Reason)
}

// ErrNoModuleRoot is returned when no go.mod is found above a directory.
var ErrNoModuleRoot = errors.New("archtest: no go.mod found")

// DeniedStd returns the standard-library packages a layer's non-test files
// must not import. An entry also denies every package below it.
func DeniedStd(l Layer) []string {
	switch l {
	case LayerCore, LayerPure:
		return []string{
			"os", "net", "io/fs", "io/ioutil", "log", "syscall", "math/rand", "crypto/rand",
			"runtime/debug", "plugin", "unsafe", "text/template", "testing", "C",
		}
	case LayerIO, LayerEntry, LayerTooling:
		return []string{"os/exec", "syscall", "plugin", "unsafe", "text/template", "testing", "C"}
	}
	return []string{""} // unknown layer: deny everything (empty prefix matches all)
}

// TestDeniedStd lists std packages no _test.go file may import.
func TestDeniedStd() []string {
	return []string{"unsafe", "os/exec", "plugin", "text/template", "C"}
}

// TestExternal lists external modules every _test.go file may import.
func TestExternal() []string {
	return []string{
		"pgregory.net/rapid", "github.com/stretchr/testify",
		"sigs.k8s.io/yaml", "github.com/santhosh-tekuri/jsonschema",
	}
}

// FindModuleRoot walks up from dir to the directory containing go.mod.
func FindModuleRoot(dir string) (string, error) {
	d, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("archtest: resolve %q: %w", dir, err)
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", fmt.Errorf("%w above %s", ErrNoModuleRoot, dir)
		}
		d = parent
	}
}

// GoFiles returns every .go file under root as sorted, slash-separated,
// root-relative paths. Hidden, underscore, testdata and vendor directories are skipped.
func GoFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".go") {
			rel, relErr := filepath.Rel(root, p)
			if relErr != nil {
				return fmt.Errorf("archtest: relative path for %s: %w", p, relErr)
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("archtest: walk %s: %w", root, err)
	}
	slices.Sort(files)
	return files, nil
}

func skipDir(name string) bool {
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") ||
		name == "testdata" || name == "vendor" || name == "node_modules"
}

// Check parses every .go file under root (imports only, all build tags) and
// reports each import the rules do not allow, and each package without a rule.
func Check(root string, rules []*Rule) ([]Violation, error) {
	files, err := GoFiles(root)
	if err != nil {
		return nil, err
	}
	byPkg := make(map[string]*Rule, len(rules))
	for _, r := range rules {
		byPkg[r.Package] = r
	}
	var out []Violation
	missing := map[string]bool{}
	for _, f := range files {
		pkg := path.Dir(f)
		rule, ok := byPkg[pkg]
		if !ok {
			if !missing[pkg] {
				missing[pkg] = true
				out = append(out, Violation{File: f, Line: 1, Reason: fmt.Sprintf("package %q has no row in the layer table (internal/archtest/layers.go)", pkg)})
			}
			continue
		}
		vs, err := checkFile(root, f, rule)
		if err != nil {
			return nil, err
		}
		out = append(out, vs...)
	}
	return out, nil
}

func checkFile(root, rel string, rule *Rule) ([]Violation, error) {
	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, parser.ImportsOnly)
	if err != nil {
		return nil, fmt.Errorf("archtest: parse %s: %w", rel, err)
	}
	isTest := strings.HasSuffix(rel, "_test.go")
	var out []Violation
	for _, spec := range af.Imports {
		imp, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, fmt.Errorf("archtest: %s: bad import literal %s: %w", rel, spec.Path.Value, err)
		}
		if reason := checkImport(rule, imp, isTest); reason != "" {
			out = append(out, Violation{File: rel, Line: fset.Position(spec.Pos()).Line, Import: imp, Reason: reason})
		}
	}
	return out, nil
}

func checkImport(rule *Rule, imp string, isTest bool) string {
	switch {
	case imp == ModulePath || strings.HasPrefix(imp, ModulePath+"/"):
		return checkInternal(rule, strings.TrimPrefix(strings.TrimPrefix(imp, ModulePath), "/"), isTest)
	case isStd(imp):
		return checkStd(rule, imp, isTest)
	default:
		if anyPrefix(imp, rule.External) || (isTest && anyPrefix(imp, TestExternal())) {
			return ""
		}
		return fmt.Sprintf("external module not allowed for %s (layer table)", rule.Package)
	}
}

func checkInternal(rule *Rule, rel string, isTest bool) string {
	if allowedInternal(rel, rule.Internal) {
		return ""
	}
	if isTest && (rel == rule.Package || allowedInternal(rel, rule.TestInternal)) {
		return ""
	}
	return fmt.Sprintf("%s may not import module package %s (layer table)", rule.Package, rel)
}

func checkStd(rule *Rule, imp string, isTest bool) string {
	denied := DeniedStd(rule.Layer)
	if isTest {
		denied = TestDeniedStd()
	}
	if slices.Contains(rule.ExtraStd, imp) {
		return ""
	}
	for _, d := range denied {
		if matchesPrefix(imp, d) {
			return fmt.Sprintf("std package %s is forbidden in the %s layer", imp, rule.Layer)
		}
	}
	return ""
}

// isStd reports whether imp is a standard-library path (or cgo's "C").
func isStd(imp string) bool {
	first, _, _ := strings.Cut(imp, "/")
	return !strings.Contains(first, ".")
}

// matchesPrefix reports whether imp equals p or lies below p.
// The empty prefix matches everything.
func matchesPrefix(imp, p string) bool {
	return p == "" || imp == p || strings.HasPrefix(imp, p+"/")
}

func anyPrefix(imp string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && matchesPrefix(imp, p) {
			return true
		}
	}
	return false
}

func allowedInternal(rel string, allowed []string) bool {
	for _, a := range allowed {
		if base, ok := strings.CutSuffix(a, "/..."); ok {
			if matchesPrefix(rel, base) {
				return true
			}
		} else if rel == a {
			return true
		}
	}
	return false
}

// CheckFileLengths reports every non-generated .go file longer than maxLines.
func CheckFileLengths(root string, maxLines int) ([]Violation, error) {
	files, err := GoFiles(root)
	if err != nil {
		return nil, err
	}
	var out []Violation
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f))) //nolint:gosec // G304: f comes from walking the module root.
		if err != nil {
			return nil, fmt.Errorf("archtest: read %s: %w", f, err)
		}
		if isGenerated(string(data)) {
			continue
		}
		if n := countLines(data); n > maxLines {
			out = append(out, Violation{File: f, Line: n, Reason: fmt.Sprintf("file has %d lines; the limit is %d", n, maxLines)})
		}
	}
	return out, nil
}

func countLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := strings.Count(string(data), "\n")
	if data[len(data)-1] != '\n' {
		n++
	}
	return n
}

// isGenerated follows the Go convention: a line "// Code generated ... DO NOT EDIT."
// before the package clause.
func isGenerated(src string) bool {
	for line := range strings.Lines(src) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			return false
		}
		if strings.HasPrefix(line, "// Code generated ") && strings.HasSuffix(line, " DO NOT EDIT.") {
			return true
		}
	}
	return false
}
