package app

import (
	"bytes"
	"context"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/config"
	"github.com/r3oof-900/darb/internal/safeio"
)

// update rewrites the golden files. It is a developer action (task golden);
// CI never passes it and fails if tests/fixtures changes (git diff --exit-code).
var update = flag.Bool("update", false, "rewrite tests/fixtures/*/*/normalized*.golden.json")

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// copyTree copies a fixture to a fresh temporary directory: tests never read
// a fixture in place, so nothing can modify it (docs/DESIGN.md section 13).
func copyTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		if strings.HasSuffix(d.Name(), ".golden.json") {
			return nil
		}
		data, err := os.ReadFile(p) //nolint:gosec // G304: p comes from walking the fixture tree.
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600) //nolint:gosec // G703: target is inside this test's own t.TempDir().
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// k8sInputs: k8s/ is one cluster's manifests (the cluster is resolved as
// for --k8s DIR); k8s/<region>/ directories (scenario 18) are the clusters
// darb.yaml declares in those regions, passed by ARN as --k8s DIR=ARN.
func k8sInputs(t *testing.T, dir string, cfg *config.Config) []K8sDir {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "k8s"))
	if err != nil {
		return nil
	}
	var out []K8sDir
	for _, e := range entries {
		if !e.IsDir() {
			return []K8sDir{{Path: "k8s"}}
		}
		key := ""
		for i := range cfg.Clusters {
			if cfg.Clusters[i].Region == e.Name() {
				key = cfg.Clusters[i].Key(cfg.Terraform.Partition)
			}
		}
		if key == "" {
			t.Fatalf("k8s/%s: no cluster in darb.yaml has that region", e.Name())
		}
		out = append(out, K8sDir{Path: "k8s/" + e.Name(), Cluster: key})
	}
	return out
}

// scansFor maps golden file names to the inputs of a fixture variant.
func scansFor(t *testing.T, dir string) map[string]*Inputs {
	t.Helper()
	cfg := config.Default()
	if data, err := os.ReadFile(filepath.Join(dir, "darb.yaml")); err == nil { //nolint:gosec // G304: fixed name inside the temp copy.
		if cfg, err = config.Parse(data); err != nil {
			t.Fatalf("darb.yaml: %v", err)
		}
	}
	k8sDirs := k8sInputs(t, dir, cfg)
	mk := func() *Inputs {
		in := &Inputs{Root: dir, Config: cfg, Limits: safeio.DefaultLimits(), K8sDirs: k8sDirs}
		if exists(filepath.Join(dir, "snapshot")) {
			in.AWSSnapshots = []string{"snapshot"}
		}
		return in
	}
	scans := map[string]*Inputs{}
	hasTF := exists(filepath.Join(dir, "terraform"))
	if exists(filepath.Join(dir, "plan.json")) {
		p := mk()
		p.TerraformPlans = []PlanInput{{Path: "plan.json"}}
		if hasTF {
			p.TerraformPlans[0].ConfigDir = "terraform" // the configuration the plan was made from
		}
		scans["normalized.golden.json"] = p
		if hasTF {
			s := mk()
			s.TerraformDirs = []string{"terraform"}
			scans["normalized.static.golden.json"] = s
		}
		return scans
	}
	in := mk()
	if hasTF {
		in.TerraformDirs = []string{"terraform"}
	}
	scans["normalized.golden.json"] = in
	return scans
}

func TestGoldenFixtures(t *testing.T) {
	variants, err := filepath.Glob(filepath.Join(repoRoot(t), "tests", "fixtures", "*", "*"))
	if err != nil || len(variants) < 34 {
		t.Fatalf("expected 17 scenarios x 2 variants, found %d (%v)", len(variants), err)
	}
	for _, src := range variants {
		name := filepath.Base(filepath.Dir(src)) + "/" + filepath.Base(src)
		t.Run(name, func(t *testing.T) {
			tmp := copyTree(t, src)
			for golden, in := range scansFor(t, tmp) {
				got := loadSummary(t, in)
				if again := loadSummary(t, in); !bytes.Equal(got, again) {
					t.Fatalf("%s: two runs over the same input differ (non-deterministic output)", golden)
				}
				checkGolden(t, filepath.Join(src, golden), got)
			}
		})
	}
}

func loadSummary(t *testing.T, in *Inputs) []byte {
	t.Helper()
	l, err := Load(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Summary(l)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func checkGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: golden file next to the fixture.
	if err != nil {
		t.Fatalf("%v (run: task golden)", err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Errorf("%s is out of date; review the change and run: task golden\n%s", path, firstDiff(want, got))
	}
}

func firstDiff(want, got []byte) string {
	w, g := strings.Split(string(want), "\n"), strings.Split(string(got), "\n")
	for i := range min(len(w), len(g)) {
		if w[i] != g[i] {
			return "line " + itoa(i+1) + ":\n  want: " + w[i] + "\n  got:  " + g[i]
		}
	}
	return "lengths differ: want " + itoa(len(w)) + " lines, got " + itoa(len(g))
}

func itoa(n int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + fmtInt(n)) }

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
