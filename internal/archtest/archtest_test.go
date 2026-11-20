package archtest

import (
	"go/build"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const maxFileLines = 400

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := FindModuleRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestLayerTableIsWellFormed(t *testing.T) {
	rules := Rules()
	known := map[string]bool{}
	for _, r := range rules {
		if known[r.Package] {
			t.Errorf("duplicate row for %s", r.Package)
		}
		known[r.Package] = true
		if DeniedStd(r.Layer)[0] == "" {
			t.Errorf("%s: unknown layer %q", r.Package, r.Layer)
		}
	}
	for _, r := range rules {
		for _, dep := range append(append([]string{}, r.Internal...), r.TestInternal...) {
			base := strings.TrimSuffix(dep, "/...")
			if base == r.Package {
				t.Errorf("%s: lists itself as a dependency", r.Package)
			}
			if !strings.HasSuffix(dep, "/...") && !known[base] {
				t.Errorf("%s: allows %s, which has no row (typo?)", r.Package, dep)
			}
		}
	}
}

// TestStdSubpackagesComplete checks stdSubpackages against the installed Go
// standard library, so a new net/* package cannot slip past depguard.
func TestStdSubpackagesComplete(t *testing.T) {
	for _, r := range Rules() {
		for _, prefix := range DeniedStd(r.Layer) {
			if !shadowsExtra(prefix, r.ExtraStd) {
				continue // only prefixes with an allowed package below them are split
			}
			entries, err := os.ReadDir(filepath.Join(build.Default.GOROOT, "src", prefix))
			if err != nil {
				t.Fatal(err)
			}
			known := stdSubpackages(prefix)
			for _, de := range entries {
				pkg := prefix + "/" + de.Name()
				if de.IsDir() && de.Name() != "testdata" && de.Name() != "internal" && !slices.Contains(known, pkg) {
					t.Errorf("stdSubpackages(%q) is missing %s", prefix, pkg)
				}
			}
		}
	}
}

func TestArnIsLeaf(t *testing.T) {
	for _, r := range Rules() {
		if r.Package == "internal/arn" && (len(r.Internal) > 0 || len(r.External) > 0) {
			t.Fatalf("internal/arn must be a leaf package, got Internal=%v External=%v", r.Internal, r.External)
		}
	}
}

// TestLayerTableIsAcyclic proves dependencies point one way only.
func TestLayerTableIsAcyclic(t *testing.T) {
	rules := Rules()
	deps := map[string][]string{}
	for _, r := range rules {
		for _, in := range r.Internal {
			deps[r.Package] = append(deps[r.Package], expand(in, rules)...)
		}
	}
	const (
		unvisited = iota
		visiting
		done
	)
	state := map[string]int{}
	var visit func(p string, trail []string)
	visit = func(p string, trail []string) {
		switch state[p] {
		case visiting:
			t.Fatalf("dependency cycle: %s -> %s", strings.Join(trail, " -> "), p)
		case done:
			return
		}
		state[p] = visiting
		for _, d := range deps[p] {
			visit(d, append(trail, p))
		}
		state[p] = done
	}
	for _, r := range rules {
		visit(r.Package, nil)
	}
}

func expand(entry string, rules []*Rule) []string {
	base, ok := strings.CutSuffix(entry, "/...")
	if !ok {
		return []string{entry}
	}
	var out []string
	for _, r := range rules {
		if matchesPrefix(r.Package, base) {
			out = append(out, r.Package)
		}
	}
	return out
}

func TestImportsFollowLayerTable(t *testing.T) {
	vs, err := Check(moduleRoot(t), Rules())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		t.Error(v.String())
	}
}

func TestFileLengthLimit(t *testing.T) {
	vs, err := CheckFileLengths(moduleRoot(t), maxFileLines)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		t.Error(v.String())
	}
}

// TestGeneratedFilesInSync fails when .golangci.yml or docs/DESIGN.md differ from
// what the layer table generates. Fix with: task gen
func TestGeneratedFilesInSync(t *testing.T) {
	root := moduleRoot(t)
	rules := Rules()
	cases := []struct {
		file, region, want string
	}{
		{".golangci.yml", RegionDepguard, RenderDepguard(rules)},
		{".golangci.yml", RegionCorePaths, RenderCorePaths(rules)},
		{"docs/DESIGN.md", RegionLayerDoc, RenderLayerDoc(rules)},
	}
	for _, c := range cases {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(c.file))) //nolint:gosec // G304: c.file is a fixed repository path from the table above.
		if err != nil {
			t.Fatal(err)
		}
		got, err := ExtractRegion(strings.ReplaceAll(string(data), "\r\n", "\n"), c.region)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if got != c.want {
			t.Errorf("%s region %q is out of date with internal/archtest/layers.go; run: task gen", c.file, c.region)
		}
	}
}
