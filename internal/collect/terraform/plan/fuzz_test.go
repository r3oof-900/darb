package plan

import (
	"os"
	"testing"

	"github.com/r3oof-900/darb/internal/coverage"
)

// FuzzPlanJSON: any input either fails cleanly or converts without panicking.
func FuzzPlanJSON(f *testing.F) {
	if seed, err := os.ReadFile("testdata/plan.json"); err == nil {
		f.Add(seed)
	}
	f.Add([]byte(`{"format_version":"1.2","planned_values":{"root_module":{"resources":[{"address":"a.b","values":{"x":[{"y":1}]}}]}},
		"resource_changes":[{"address":"a.b","change":{"after_unknown":{"x":[{"y":true}],"z":true}}}]}`))
	f.Fuzz(func(_ *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		_, _ = fromJSON("fuzz.json", data, &coverage.Recorder{}, nil)
	})
}
