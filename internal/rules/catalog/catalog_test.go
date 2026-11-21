package catalog

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

// pinned is the rule set (ID@version) of each catalog version. Changing a
// rule's ID set or a version without bumping Version, and adding the new
// set here, fails the test (DESIGN.md §8).
var pinned = map[string][]string{
	"1.0.0": {
		"CLAPA-PATH-001@1.0.0", "CLAPA-PATH-002@1.0.0", "CLAPA-PATH-003@1.0.0",
		"CLAPA-POST-001@1.0.0", "CLAPA-POST-002@1.0.0", "CLAPA-POST-003@1.0.0", "CLAPA-POST-004@1.0.0",
		"CLAPA-POST-005@1.0.0", "CLAPA-POST-006@1.0.0", "CLAPA-POST-007@1.0.0",
	},
	// 1.1.0 (Phase 5 review): CLAPA-POST-008, a broad grant of a sensitive action.
	"1.1.0": {
		"CLAPA-PATH-001@1.0.0", "CLAPA-PATH-002@1.0.0", "CLAPA-PATH-003@1.0.0",
		"CLAPA-POST-001@1.0.0", "CLAPA-POST-002@1.0.0", "CLAPA-POST-003@1.0.0", "CLAPA-POST-004@1.0.0",
		"CLAPA-POST-005@1.0.0", "CLAPA-POST-006@1.0.0", "CLAPA-POST-007@1.0.0", "CLAPA-POST-008@1.0.0",
	},
}

func TestCatalogVersion(t *testing.T) {
	reg, err := New()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range reg.Rules() {
		got = append(got, r.Meta().ID+"@"+r.Meta().Version)
	}
	slices.Sort(got)
	want, ok := pinned[Version]
	if !ok {
		t.Fatalf("catalog %s is not pinned; add its rule set: %s", Version, strings.Join(got, " "))
	}
	if !slices.Equal(got, want) {
		t.Fatalf("the rule set changed without a catalog version bump:%s got  %v%s want %v", "\t", got, "\t", want)
	}
	for _, v := range slices.Sorted(maps.Keys(pinned)) {
		if v != Version && slices.Equal(pinned[v], got) {
			t.Errorf("catalog %s has the same rule set as %s", Version, v)
		}
	}
}
