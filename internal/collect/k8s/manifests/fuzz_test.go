package manifests

import (
	"os"
	"testing"

	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/safeio"
)

// FuzzDocuments: any YAML/JSON input is decoded or reported, never a panic.
func FuzzDocuments(f *testing.F) {
	for _, p := range []string{"testdata/m/app.yaml", "testdata/m/bomb.yaml", "testdata/m/broken.yaml"} {
		if seed, err := os.ReadFile(p); err == nil { //nolint:gosec // G304: p is one of the fixed seed paths above.
			f.Add(seed)
		}
	}
	f.Add([]byte("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec: {containers: [{name: c}]}\n---\n- a\n"))
	s, err := newSerializer()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		d := &decoder{rec: &coverage.Recorder{}, limits: safeio.Limits{MaxFileBytes: 1 << 16, MaxDepth: 64}, serializer: s}
		_ = d.file("fuzz.yaml", data)
	})
}
