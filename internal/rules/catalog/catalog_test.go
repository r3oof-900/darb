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
	// 2.0.0: the rename to darb changed every rule ID (and fingerprint); the
	// rules and their versions are those of 1.2.1. Catalog versions 1.0.0 to
	// 1.2.1 used the former IDs; their sets are in the git history of this
	// file.
	"2.0.0": {
		"DARB-PATH-001@1.0.0", "DARB-PATH-002@1.0.0", "DARB-PATH-003@1.0.0",
		"DARB-POST-001@1.0.1", "DARB-POST-002@1.0.0", "DARB-POST-003@1.0.0", "DARB-POST-004@1.0.0",
		"DARB-POST-005@1.0.0", "DARB-POST-006@1.0.0", "DARB-POST-007@1.0.0", "DARB-POST-008@1.1.0",
	},
	// 2.1.0 (after v0.1.0-rc.1): the path rules also reach data stores no
	// rule classifies (classification unclassified); fingerprints are
	// unchanged, so the rules' minor versions move.
	"2.1.0": {
		"DARB-PATH-001@1.1.0", "DARB-PATH-002@1.1.0", "DARB-PATH-003@1.1.0",
		"DARB-POST-001@1.0.1", "DARB-POST-002@1.0.0", "DARB-POST-003@1.0.0", "DARB-POST-004@1.0.0",
		"DARB-POST-005@1.0.0", "DARB-POST-006@1.0.0", "DARB-POST-007@1.0.0", "DARB-POST-008@1.1.0",
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
