package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/r3oof-900/clapa/pkg/schema"
)

// schemas/report.v1.schema.json describes clapa-report/v1 (pkg/schema).
// Every scenario's JSON report validates against it, and the schema and
// the Go types describe the same fields: a field added to one and not the
// other fails (every object in the schema is closed).

func reportSchema(t *testing.T) (sch *jsonschema.Schema, raw map[string]any) {
	t.Helper()
	file := filepath.Join(repoRoot(t), "schemas", "report.v1.schema.json")
	data, err := os.ReadFile(file) //nolint:gosec // G304: the repository's own schema.
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if aerr := c.AddResource("report.v1.schema.json", doc); aerr != nil {
		t.Fatal(aerr)
	}
	sch, err = c.Compile("report.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	return sch, raw
}

func TestEveryReportMatchesTheSchema(t *testing.T) {
	sch, _ := reportSchema(t)
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
			if werr := Write(&out, "json", Report(a, in.Config, DefaultFailOn)); werr != nil {
				t.Fatal(werr)
			}
			doc, err := jsonschema.UnmarshalJSON(&out)
			if err != nil {
				t.Fatal(err)
			}
			if err := sch.Validate(doc); err != nil {
				t.Errorf("%s (%s): the report does not match the schema: %v", name, golden, err)
			}
			checked++
		}
	}
	if checked < 40 {
		t.Fatalf("only %d reports validated", checked)
	}
}

// Every Go field is in the schema and every schema property is a Go field.
func TestSchemaDescribesTheGoTypes(t *testing.T) {
	_, raw := reportSchema(t)
	defs, _ := raw["$defs"].(map[string]any)
	objects := map[reflect.Type]map[string]any{reflect.TypeFor[schema.Report](): raw}
	for typ, def := range map[reflect.Type]string{
		reflect.TypeFor[schema.Tool](): "tool", reflect.TypeFor[schema.ThreatModel](): "threatModel",
		reflect.TypeFor[schema.Summary](): "summary", reflect.TypeFor[schema.Location](): "location",
		reflect.TypeFor[schema.Factors](): "factors", reflect.TypeFor[schema.Finding](): "finding",
		reflect.TypeFor[schema.FixStep](): "fixStep", reflect.TypeFor[schema.Default](): "default",
		reflect.TypeFor[schema.IntendedAccess](): "intendedAccess", reflect.TypeFor[schema.Coverage](): "coverage",
		reflect.TypeFor[schema.Gap](): "gap", reflect.TypeFor[schema.Note](): "note",
		reflect.TypeFor[schema.Graph](): "graph", reflect.TypeFor[schema.Rule](): "rule",
	} {
		d, ok := defs[def].(map[string]any)
		if !ok {
			t.Fatalf("$defs.%s is missing", def)
		}
		objects[typ] = d
	}
	for typ, obj := range objects {
		props, _ := obj["properties"].(map[string]any)
		if obj["additionalProperties"] != false {
			t.Errorf("%s: the schema object must be closed", typ.Name())
		}
		var fields []string
		for i := range typ.NumField() {
			name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
			fields = append(fields, name)
			if _, ok := props[name]; !ok {
				t.Errorf("%s.%s (%q) is not in the schema", typ.Name(), typ.Field(i).Name, name)
			}
		}
		for name := range props {
			if !slices.Contains(fields, name) {
				t.Errorf("the schema's %q is not a field of %s", name, typ.Name())
			}
		}
	}
}
