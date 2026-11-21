package verify

import (
	"strings"
	"testing"
)

// Each rule of level 1 rejects on its own, and level 2 reports every
// difference between the in-memory and the on-file result.
func TestCompareRules(t *testing.T) {
	before := &Result{
		Findings: map[string]string{"target": "high", "other": "medium"},
		Intended: map[string]string{"api read A": "verified", "api read B": "unconfirmed"},
	}
	ok := &Result{Findings: map[string]string{"other": "medium"}, Intended: map[string]string{"api read A": "verified", "api read B": "verified"}}
	if r := Compare(before, ok, "target"); len(r) != 0 {
		t.Fatalf("an acceptable result was rejected: %v", r)
	}
	for _, c := range []struct {
		name  string
		after *Result
		want  string
	}{
		{"target remains", &Result{Findings: map[string]string{"target": "high", "other": "medium"}, Intended: before.Intended}, "is still reported"},
		{"new finding", &Result{Findings: map[string]string{"other": "medium", "new": "low"}, Intended: before.Intended}, "a new finding appears"},
		{"severity rises", &Result{Findings: map[string]string{"other": "high"}, Intended: before.Intended}, "rises from medium to high"},
		{"intended worse", &Result{Findings: map[string]string{"other": "medium"}, Intended: map[string]string{"api read A": "not-satisfied", "api read B": "unconfirmed"}}, "goes from verified to not-satisfied"},
		{"intended missing", &Result{Findings: map[string]string{"other": "medium"}, Intended: map[string]string{"api read B": "unconfirmed"}}, "goes from verified to missing"},
	} {
		r := Compare(before, c.after, "target")
		if len(r) != 1 || !strings.Contains(r[0], c.want) {
			t.Errorf("%s: %v, want one reason with %q", c.name, r, c.want)
		}
	}
}

func TestSame(t *testing.T) {
	mem := &Result{Findings: map[string]string{"a": "low"}, Intended: map[string]string{"x": "verified"}, ExitCode: 0}
	if d := Same(mem, mem); len(d) != 0 {
		t.Fatalf("identical results differ: %v", d)
	}
	files := &Result{Findings: map[string]string{"a": "medium", "b": "low"}, Intended: map[string]string{"x": "unconfirmed"}, ExitCode: 1}
	d := strings.Join(Same(mem, files), "; ")
	for _, want := range []string{"finding a: low in memory, medium after the patch", "finding b appears only after the patch", "intended access x", "exit code: 0 in memory, 1 after the patch"} {
		if !strings.Contains(d, want) {
			t.Errorf("missing %q in %s", want, d)
		}
	}
}
