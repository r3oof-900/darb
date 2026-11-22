package hclstatic

import (
	"os"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/safeio"
)

// FuzzModule: any HCL source either fails to parse (reported) or is
// evaluated and converted without panicking.
func FuzzModule(f *testing.F) {
	if seed, err := os.ReadFile("testdata/basic/main.tf"); err == nil {
		f.Add(seed)
	}
	f.Add([]byte(`locals { a = "${local.b}"
 b = "${local.a}" }
resource "x" "y" { z = jsonencode({ k = [aws_kms_key.k.arn, var.v, "${upper("q")}"] }) }`))
	f.Fuzz(func(_ *testing.T, src []byte) {
		if len(src) > 1<<15 {
			return
		}
		file, diags := hclsyntax.ParseConfig(src, "fuzz.tf", hcl.InitialPos)
		if diags.HasErrors() {
			return
		}
		body, _ := file.Body.(*hclsyntax.Body)
		m := &rootModule{
			prefix: ".", rec: &coverage.Recorder{}, limits: safeio.DefaultLimits(), src: map[string][]byte{"fuzz.tf": src},
			vars: map[string]*hclsyntax.Attribute{}, locals: map[string]*hclsyntax.Attribute{},
		}
		m.loadBody(body)
		m.evaluate()
		_ = m.resources()
		_ = m.providers()
	})
}
