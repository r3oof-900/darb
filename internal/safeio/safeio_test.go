package safeio

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadFileLimits(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "a", "ok.tf"), "x")
	write(t, filepath.Join(root, "big.json"), strings.Repeat("x", 100))
	lim := Limits{MaxFileBytes: 10, MaxDepth: 4}
	if data, err := ReadFile(root, "a/ok.tf", lim); err != nil || string(data) != "x" {
		t.Fatalf("ok file: %q %v", data, err)
	}
	cases := map[string]error{
		"big.json":           ErrTooLarge,
		"../outside.tf":      ErrOutsideRoot,
		"a/../../outside.tf": ErrOutsideRoot,
		"a":                  ErrNotRegular,
	}
	for rel, want := range cases {
		if _, err := ReadFile(root, rel, lim); !errors.Is(err, want) {
			t.Errorf("%s: got %v, want %v", rel, err, want)
		}
	}
	if _, err := ReadFile(root, "missing.tf", lim); err == nil {
		t.Error("missing file must fail")
	}
	if _, err := ReadFile(filepath.Join(root, "nope"), "x", lim); err == nil {
		t.Error("missing root must fail")
	}
}

func TestReadFileRejectsSymlinkEscape(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	write(t, filepath.Join(outside, "secret"), "s")
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := ReadFile(root, "link", DefaultLimits()); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("got %v, want ErrOutsideRoot", err)
	}
}

func TestWalk(t *testing.T) {
	root := t.TempDir()
	for _, f := range []string{"main.tf", "mod/b.TF", "k8s/d.yaml", ".terraform/x.tf", "readme.md"} {
		write(t, filepath.Join(root, filepath.FromSlash(f)), "")
	}
	got, err := Walk(root, []string{".tf"})
	if err != nil || strings.Join(got, ",") != "main.tf,mod/b.TF" {
		t.Fatalf("got %v %v", got, err)
	}
	if _, err := Walk(filepath.Join(root, "missing"), []string{".tf"}); err == nil {
		t.Error("missing root must fail")
	}
}

func TestCheckJSONDepth(t *testing.T) {
	if err := CheckJSONDepth([]byte(`{"a":[{"b":"[[[[[[\"]]"}]}`), 3); err != nil {
		t.Errorf("brackets in strings must not count: %v", err)
	}
	if err := CheckJSONDepth([]byte(`[[[[1]]]]`), 3); !errors.Is(err, ErrTooDeep) {
		t.Errorf("got %v", err)
	}
	if DefaultLimits().MaxDepth != 64 {
		t.Error("default depth")
	}
}
