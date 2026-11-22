package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The official SARIF 2.1.0 schema (OASIS, errata 01), vendored unchanged
// from https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
// on 2026-11-22; its SHA-256 is pinned so a changed copy fails.
const sarifSchemaSHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"

func sarifSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	file := filepath.Join(repoRoot(t), "internal", "report", "sarif", "testdata", "sarif-schema-2.1.0.json")
	data, err := os.ReadFile(file) //nolint:gosec // G304: the repository's own test data.
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != sarifSchemaSHA256 {
		t.Fatalf("%s is not the vendored OASIS schema", file)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if aerr := c.AddResource("sarif-schema-2.1.0.json", doc); aerr != nil {
		t.Fatal(aerr)
	}
	sch, err := c.Compile("sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

// The SARIF report of every fixture variant validates against the official
// schema (DESIGN.md §11).
func TestEverySARIFReportMatchesTheOfficialSchema(t *testing.T) {
	sch := sarifSchema(t)
	variants, err := filepath.Glob(filepath.Join(repoRoot(t), "tests", "fixtures", "*", "*"))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, variant := range variants {
		if fi, err := os.Stat(variant); err != nil || !fi.IsDir() {
			continue
		}
		name := filepath.Base(filepath.Dir(variant)) + "/" + filepath.Base(variant)
		for golden, in := range scansFor(t, copyTree(t, variant)) {
			l, err := Load(context.Background(), in)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			a, err := Analyze(l, in.Config, DefaultFailOn)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if werr := Write(&out, "sarif", Report(a, in.Config, DefaultFailOn)); werr != nil {
				t.Fatal(werr)
			}
			doc, err := jsonschema.UnmarshalJSON(&out)
			if err != nil {
				t.Fatal(err)
			}
			if err := sch.Validate(doc); err != nil {
				t.Errorf("%s (%s): the SARIF report does not match the official schema: %v", name, golden, err)
			}
			checked++
		}
	}
	if checked < 40 {
		t.Fatalf("only %d SARIF reports validated", checked)
	}
	// The schema is applied, not just loaded: a result level SARIF does not
	// define, and a run without its tool, are rejected.
	for _, bad := range []string{
		`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"darb"}},"results":[{"level":"fatal","message":{"text":"x"}}]}]}`,
		`{"version":"2.1.0","runs":[{"results":[]}]}`,
	} {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(bad)))
		if err != nil {
			t.Fatal(err)
		}
		if sch.Validate(doc) == nil {
			t.Errorf("invalid SARIF accepted: %s", bad)
		}
	}
}
