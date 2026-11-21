package awslive

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// docs/PERMISSIONS.md grants exactly the APIs the collector calls.
func TestPermissionsDocument(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "PERMISSIONS.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "```json")
	block, _, ok2 := strings.Cut(rest, "```")
	if !ok || !ok2 {
		t.Fatal("docs/PERMISSIONS.md has no json policy block")
	}
	var doc struct {
		Statement []struct {
			Effect   string   `json:"Effect"`
			Action   []string `json:"Action"`
			Resource string   `json:"Resource"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(block), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Statement) != 1 || doc.Statement[0].Effect != "Allow" {
		t.Fatalf("statements %+v", doc.Statement)
	}
	got := doc.Statement[0].Action
	want := allowedAPIs()
	slices.Sort(want)
	if !slices.IsSorted(got) || !slices.Equal(got, want) {
		t.Fatalf("PERMISSIONS.md actions\n  %v\nthe collector calls\n  %v", got, want)
	}
}
