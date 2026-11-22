package archtest

import "slices"

// Layer classifies a package by what it may do. See docs/DESIGN.md section 3.1.
type Layer string

// Layers, from most to least restricted.
const (
	// LayerCore packages are pure functions over data: no I/O, no logging, no
	// package-level mutable state, no wall clock, no randomness.
	LayerCore Layer = "core"
	// LayerPure packages do no I/O but may use vetted external parsing libraries
	// and immutable package-level tables.
	LayerPure Layer = "pure"
	// LayerIO packages may perform I/O.
	LayerIO Layer = "io"
	// LayerEntry packages wire the pipeline (app, cli, main).
	LayerEntry Layer = "entry"
	// LayerTooling packages are repository tooling, never linked into darb.
	LayerTooling Layer = "tooling"
)

// ModulePath is the Go module path of this repository.
const ModulePath = "github.com/r3oof-900/darb"

// Rule states exactly what one package may import.
type Rule struct {
	// Package is the module-relative import path, e.g. "internal/eval".
	Package string
	// Layer selects the standard-library restrictions.
	Layer Layer
	// Internal lists module-relative packages this package may import.
	// An entry "x/..." allows x and every package below it.
	Internal []string
	// External lists external module path prefixes this package may import.
	// An entry matches the import path exactly or as a "prefix/" prefix.
	External []string
	// ExtraStd lists standard-library packages allowed despite the layer's denials.
	ExtraStd []string
	// TestInternal lists module packages that only _test.go files may import.
	TestInternal []string
}

// External module prefixes, named once so the table stays readable.
const (
	extCobra     = "github.com/spf13/cobra"
	extHCL       = "github.com/hashicorp/hcl/v2"
	extTFJSON    = "github.com/hashicorp/terraform-json"
	extCty       = "github.com/zclconf/go-cty"
	extK8sAPI    = "k8s.io/api"
	extK8sMach   = "k8s.io/apimachinery"
	extClientGo  = "k8s.io/client-go"
	extSigsYAML  = "sigs.k8s.io/yaml"
	extAWSSDK    = "github.com/aws/aws-sdk-go-v2"
	extSmithy    = "github.com/aws/smithy-go"
	extXSync     = "golang.org/x/sync"
	extUnifiedDF = "github.com/aymanbagabas/go-udiff"
	extYAMLv3    = "go.yaml.in/yaml/v3"
	extXMod      = "golang.org/x/mod"
	extXNetHTML  = "golang.org/x/net/html" // tests of the HTML report parse its output
)

// coreModel is the set of core packages most rule-layer packages build on.
func coreModel(extra ...string) []string {
	return plus([]string{"internal/model", "internal/arn"}, extra...)
}

// plus returns a new slice holding base followed by more. It never aliases
// base, so one base list can be extended differently for several rules.
func plus(base []string, more ...string) []string {
	return slices.Concat(base, more)
}

// Rules returns the dependency table. It is the single source of truth for
// archtest, the generated depguard configuration and docs/DESIGN.md.
func Rules() []*Rule {
	rs := coreRules()
	rs = append(rs, pureRules()...)
	rs = append(rs, ioRules()...)
	rs = append(rs, entryRules()...)
	rs = append(rs, toolingRules()...)
	return rs
}

func coreRules() []*Rule {
	ruleDeps := coreModel("internal/eval", "internal/eval/match", "internal/graph", "internal/paths", "internal/rules", "internal/scoring", "internal/access")
	return []*Rule{
		{Package: "internal/arn", Layer: LayerCore},
		{Package: "internal/model", Layer: LayerCore, Internal: []string{"internal/arn"}},
		{Package: "internal/iampolicy", Layer: LayerCore, Internal: coreModel()},
		{Package: "internal/eval/match", Layer: LayerCore, Internal: coreModel()},
		// net/netip is pure address parsing (IpAddress/NotIpAddress); the
		// "net" denial exists to keep network I/O out of the core.
		{Package: "internal/eval/condition", Layer: LayerCore, Internal: coreModel(), ExtraStd: []string{"net/netip"}},
		{
			Package: "internal/eval", Layer: LayerCore,
			Internal:     coreModel("internal/eval/match", "internal/eval/condition"),
			TestInternal: []string{"internal/iampolicy"},
		},
		{Package: "internal/graph", Layer: LayerCore, Internal: []string{"internal/model", "internal/eval"}},
		{
			Package: "internal/access", Layer: LayerCore,
			Internal:     coreModel("internal/eval", "internal/eval/match", "internal/eval/condition", "internal/graph", "internal/scoring"),
			TestInternal: []string{"internal/iampolicy"},
		},
		{Package: "internal/paths", Layer: LayerCore, Internal: []string{"internal/model", "internal/graph"}, TestInternal: []string{"internal/eval"}},
		{Package: "internal/classify", Layer: LayerCore, Internal: coreModel()},
		{Package: "internal/rules", Layer: LayerCore, Internal: coreModel("internal/eval", "internal/graph", "internal/paths", "internal/scoring")},
		{Package: "internal/rules/pathrules", Layer: LayerCore, Internal: ruleDeps},
		{Package: "internal/rules/posture", Layer: LayerCore, Internal: ruleDeps, TestInternal: []string{"internal/iampolicy"}},
		{Package: "internal/rules/escalation", Layer: LayerCore, Internal: ruleDeps},
		{Package: "internal/rules/catalog", Layer: LayerCore, Internal: []string{
			"internal/rules", "internal/rules/pathrules", "internal/rules/posture", "internal/rules/escalation",
		}},
		{Package: "internal/scoring", Layer: LayerCore, Internal: []string{"internal/model", "internal/eval", "internal/graph", "internal/paths"}},
		{Package: "internal/findings", Layer: LayerCore, Internal: []string{
			"internal/model", "internal/graph", "internal/paths", "internal/rules", "internal/scoring",
		}},
		{Package: "internal/remediate", Layer: LayerCore, Internal: coreModel(
			"internal/iampolicy", "internal/eval", "internal/graph", "internal/paths", "internal/rules", "internal/findings",
		)},
		{Package: "internal/verify", Layer: LayerCore, Internal: []string{
			"internal/model", "internal/eval", "internal/graph", "internal/access", "internal/paths",
			"internal/rules", "internal/remediate", "internal/findings",
		}},
		{Package: "internal/coverage", Layer: LayerCore},
	}
}

func pureRules() []*Rule {
	normDeps := coreModel("internal/normalize", "internal/coverage")
	return []*Rule{
		{Package: "pkg/schema", Layer: LayerPure},
		// log/slog: the redacting log handler is a slog.Handler (it logs nothing).
		{Package: "internal/redact", Layer: LayerPure, ExtraStd: []string{"log/slog"}},
		{Package: "internal/version", Layer: LayerPure},
		{Package: "internal/managedpolicies", Layer: LayerPure},
		{Package: "internal/config", Layer: LayerPure, Internal: coreModel("internal/classify"), External: []string{extSigsYAML, extYAMLv3}},
		{Package: "internal/collect/tfraw", Layer: LayerPure, External: []string{extHCL, extTFJSON, extCty}},
		{Package: "internal/collect/k8sraw", Layer: LayerPure, External: []string{extK8sAPI, extK8sMach}},
		{Package: "internal/collect/awsraw", Layer: LayerPure, Internal: []string{"internal/coverage"}, External: []string{extAWSSDK}},
		{Package: "internal/normalize", Layer: LayerPure, Internal: coreModel("internal/coverage")},
		{
			Package: "internal/normalize/terraform", Layer: LayerPure,
			Internal:     plus(normDeps, "internal/iampolicy", "internal/managedpolicies", "internal/collect/tfraw"),
			External:     []string{extHCL, extTFJSON, extCty},
			TestInternal: []string{"internal/collect", "internal/collect/terraform/hclstatic", "internal/collect/terraform/plan", "internal/safeio", "internal/eval", "internal/eval/match", "internal/eval/condition"},
		},
		{
			Package: "internal/normalize/k8s", Layer: LayerPure,
			Internal:     plus(normDeps, "internal/collect/k8sraw"),
			External:     []string{extK8sAPI, extK8sMach, extSigsYAML},
			TestInternal: []string{"internal/collect", "internal/collect/k8s/manifests", "internal/safeio"},
		},
		{
			// net/url only for URL-decoding IAM policy documents (no network).
			Package: "internal/normalize/aws", Layer: LayerPure,
			Internal:     plus(normDeps, "internal/iampolicy", "internal/managedpolicies", "internal/collect/awsraw"),
			External:     []string{extAWSSDK},
			ExtraStd:     []string{"net/url"},
			TestInternal: []string{"internal/collect", "internal/collect/awssnapshot", "internal/safeio"},
		},
		{
			Package: "internal/patch", Layer: LayerPure,
			Internal: []string{"internal/model", "internal/iampolicy", "internal/remediate", "internal/findings"},
			External: []string{extHCL, extCty, extUnifiedDF, extYAMLv3},
		},
		{Package: "internal/report", Layer: LayerPure, Internal: []string{
			"pkg/schema", "internal/model", "internal/graph", "internal/paths", "internal/rules",
			"internal/scoring", "internal/findings", "internal/coverage", "internal/version",
		}},
		{Package: "internal/report/console", Layer: LayerPure, Internal: []string{"internal/report", "pkg/schema"}},
		{Package: "internal/report/jsonreport", Layer: LayerPure, Internal: []string{"internal/report", "pkg/schema"}},
		{Package: "internal/report/sarif", Layer: LayerPure, Internal: []string{"internal/report", "pkg/schema"}},
		{Package: "internal/report/htmlreport", Layer: LayerPure, Internal: []string{"internal/report", "pkg/schema"}, External: []string{extXNetHTML}},
		{Package: "internal/report/junit", Layer: LayerPure, Internal: []string{"internal/report", "pkg/schema"}},
		{Package: "internal/report/markdown", Layer: LayerPure, Internal: []string{"internal/report", "pkg/schema"}},
		{Package: "internal/llm", Layer: LayerPure, Internal: []string{"pkg/schema", "internal/redact", "internal/llm/pseudonymize"}},
		// The only package that sends anything to an LLM provider (--llm).
		{Package: "internal/llm/claude", Layer: LayerIO, Internal: []string{"internal/llm"}, TestInternal: []string{"internal/llm/pseudonymize"}},
		{Package: "internal/llm/pseudonymize", Layer: LayerPure},
	}
}

func ioRules() []*Rule {
	collectDeps := []string{"internal/collect", "internal/coverage", "internal/safeio"}
	k8sExt := []string{extK8sAPI, extK8sMach, extClientGo}
	return []*Rule{
		{Package: "internal/safeio", Layer: LayerIO},
		{Package: "internal/collect", Layer: LayerIO, Internal: []string{"internal/coverage", "internal/safeio"}, ExtraStd: []string{"net/url"}, TestInternal: []string{"internal/model"}},
		{
			Package: "internal/collect/terraform/plan", Layer: LayerIO,
			Internal: plus(collectDeps, "internal/collect/tfraw"),
			External: []string{extTFJSON, extHCL},
			ExtraStd: []string{"os/exec"},
		},
		{
			Package: "internal/collect/terraform/hclstatic", Layer: LayerIO,
			Internal: plus(collectDeps, "internal/collect/tfraw"),
			External: []string{extHCL, extCty},
		},
		{
			Package: "internal/collect/k8s/manifests", Layer: LayerIO,
			Internal: plus(collectDeps, "internal/collect/k8sraw"),
			External: plus(k8sExt, extSigsYAML, extYAMLv3),
		},
		{
			Package: "internal/collect/k8s/live", Layer: LayerIO,
			Internal: []string{"internal/collect", "internal/coverage", "internal/collect/k8sraw"},
			External: plus(k8sExt, extAWSSDK, extSmithy, extXSync),
			TestInternal: []string{
				"internal/collect/k8s/manifests", "internal/normalize", "internal/normalize/k8s", "internal/safeio", "internal/model",
			},
		},
		{
			// Test support only: imported by _test.go files, never linked into darb.
			Package: "internal/collect/k8s/live/k8sfake", Layer: LayerIO,
			Internal: []string{"internal/collect/k8s/live"},
			External: k8sExt,
		},
		{
			Package: "internal/collect/awssnapshot", Layer: LayerIO,
			Internal: plus(collectDeps, "internal/collect/awsraw"),
			External: []string{extAWSSDK},
		},
		{
			Package: "internal/collect/awslive", Layer: LayerIO,
			Internal:     []string{"internal/collect", "internal/coverage", "internal/collect/awsraw"},
			External:     []string{extAWSSDK, extSmithy, extXSync},
			TestInternal: []string{"internal/collect/awslive/awsfake"},
		},
		{
			// Test support only: imported by _test.go files, never linked into darb.
			Package: "internal/collect/awslive/awsfake", Layer: LayerIO,
			Internal: []string{"internal/collect/awslive"},
			External: []string{extAWSSDK, extSmithy},
		},
	}
}

func entryRules() []*Rule {
	return []*Rule{
		{
			Package: "internal/app", Layer: LayerEntry,
			Internal: []string{
				"internal/config", "internal/collect/...", "internal/normalize/...", "internal/model",
				"internal/classify", "internal/iampolicy", "internal/eval", "internal/access",
				"internal/graph", "internal/paths", "internal/rules", "internal/rules/catalog",
				"internal/scoring", "internal/findings", "internal/remediate", "internal/verify",
				"internal/patch", "internal/report/...", "internal/llm/...", "internal/coverage",
				"internal/redact", "internal/safeio", "internal/version", "internal/managedpolicies",
				"pkg/schema",
			},
			External:     []string{extXSync},
			TestInternal: []string{"internal/eval/condition", "internal/eval/match", "internal/collect/awslive/awsfake"},
		},
		{
			Package: "internal/cli", Layer: LayerEntry,
			Internal: []string{
				"internal/app", "internal/config", "internal/rules", "internal/rules/catalog",
				"internal/version", "internal/redact", "pkg/schema",
			},
			External: []string{extCobra},
			// os/exec only for `git status` before `remediate --write`.
			ExtraStd:     []string{"os/exec"},
			TestInternal: []string{"internal/collect/awslive", "internal/collect/awslive/awsfake", "internal/collect/k8s/live/k8sfake", "internal/llm"},
		},
		{Package: "cmd/darb", Layer: LayerEntry, Internal: []string{"internal/cli"}},
	}
}

func toolingRules() []*Rule {
	return []*Rule{
		{Package: "internal/archtest", Layer: LayerTooling},
		{Package: "tools/archgen", Layer: LayerTooling, Internal: []string{"internal/archtest"}},
		{Package: "tools/refresh-managed-policies", Layer: LayerTooling, External: []string{extAWSSDK}},
		{Package: "tools/benchgate", Layer: LayerTooling},
		{Package: "tools/depage", Layer: LayerTooling, External: []string{extXMod, extYAMLv3}},
	}
}
