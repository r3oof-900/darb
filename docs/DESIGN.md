# CLAPA — Design

Cross-Layer Cloud Attack-Path Analyzer. This document records **what** we build,
**how**, and **why**, for every section of the build specification
(`cspm_build_prompt.md`, referred to as *the spec*; section numbers below mirror it).

Status: **Phase 1 (design + skeleton)**. Nothing described here is implemented yet
unless explicitly marked *implemented*.

Conventions used in this document:

- **Decision** — a choice we made, with the trade-off we accepted.
- **Flag** — an ambiguity or conflict in the spec, or an AWS/Kubernetes behaviour we
  are not certain about. Every flag names the safer option we picked and, where it is
  AWS/K8s behaviour, the documentation section we rely on. Each such behaviour becomes
  a test case named after that section (spec §0.6).
- **UNKNOWN** — the tool's explicit "could not evaluate" verdict. Never rendered as
  "safe".

---

## 1. Problem and non-goals

Single-layer scanners each see one layer. Real breaches chain them:
internet-facing pod → ServiceAccount → IRSA/Pod Identity → IAM role → `kms:Decrypt`
on `*` → CMK → PII bucket. CLAPA builds **one graph** of identity and permission flow
across Kubernetes and AWS, finds feasible entry → crown-jewel paths, explains each hop
with evidence, and proposes the minimal **verified** fix.

Non-goals (MVP): runtime detection, agent deployment, auto-applying fixes to live
cloud accounts, CVE/vulnerability scanning of images, compliance reporting.

## 2. Scope

MVP: AWS (IAM, STS, KMS, S3, EKS, EC2 instance profiles/IMDS, Secrets Manager, SSM
Parameter Store) + Kubernetes/EKS. Inputs: Terraform plan JSON, static HCL, K8s
manifests, offline AWS snapshots, live read-only AWS and K8s.

**Decision — extension without touching the core.** A provider or service is a
`collector` (raw types) + `normalizer` (raw → canonical model) + `rules`, registered
in `internal/app`. The core (`model`, `eval`, `graph`, `access`, `paths`, `rules`)
is provider-agnostic: it sees `Principal`, `Resource`, `PolicyDocument`, edges.
AWS-specific *semantics* that the evaluator must know (e.g. KMS key-policy
requirement, S3 bucket vs object ARNs) are expressed as **data** on the canonical
model (`Resource.AuthzTraits`), not as `if service == "kms"` in the core.
`docs/EXTENDING.md` (Phase 7) walks through adding a service end to end.

**Flag — EKS access entries.** The spec lists the `aws-auth` ConfigMap only. EKS
*access entries* (EKS API `ListAccessEntries`/`ListAssociatedAccessPolicies`) are
now the AWS-recommended way to map IAM principals to cluster permissions (EKS User
Guide › "Grant IAM users access to Kubernetes with EKS access entries"). Missing them
would produce false negatives. Decision: model both; access entries are collected in
Phase 6 (live/snapshot) and from `aws_eks_access_entry` / `aws_eks_access_policy_association`
in Terraform (Phase 3).

---

## 3. Architecture

```
collectors → normalizers → canonical model → policy evaluator → access graph
                                                                    ↓
reporters ← findings + evidence ← remediation verifier ← path engine + rules
```

### 3.1 Packages

| Stage | Package(s) | Purity |
|---|---|---|
| Collect | `internal/collect` (interfaces), `collect/terraform/{plan,hclstatic}`, `collect/k8s/{manifests,live}`, `collect/awssnapshot`, `collect/awslive` | I/O |
| Raw types | `collect/tfraw`, `collect/k8sraw`, `collect/awsraw` | pure |
| Normalize | `internal/normalize` (+ `terraform`, `k8s`, `aws`) | pure |
| Model | `internal/model`, `internal/arn`, `internal/iampolicy`, `internal/classify` | core |
| Evaluate | `internal/eval` (+ `match`, `condition`) | core |
| Graph | `internal/graph` (structure), `internal/access` (builds edges using `eval`) | core |
| Paths | `internal/paths` | core |
| Rules | `internal/rules` (+ `pathrules`, `posture`, `escalation`, `catalog`) | core |
| Findings | `internal/scoring`, `internal/findings` | core |
| Remediate | `internal/remediate` (candidates), `internal/verify` (proofs) | core |
| Patch | `internal/patch` (hclwrite edits, policy rewrite, unified diff) | pure |
| Report | `internal/report` (+ `console`, `jsonreport`, `sarif`, `htmlreport`, `junit`, `markdown`), `pkg/schema` | pure |
| Support | `internal/coverage`, `internal/redact`, `internal/config`, `internal/safeio`, `internal/version`, `internal/managedpolicies`, `internal/llm` (+ `pseudonymize`) | mixed |
| Wiring | `internal/app`, `internal/cli`, `cmd/clapa` | entry |
| Tooling | `internal/archtest`, `tools/archgen`, `tools/refresh-managed-policies` | tooling |

Layers, and what each may use from the standard library:

- **core** — pure functions over data. No I/O, no network, no logging/printing, no
  package-level mutable state, no wall clock (`time.Now` is forbidden; callers pass
  "now" in), no randomness. The std packages `os`, `net`, `io/fs`, `io/ioutil`,
  `log`, `syscall`, `math/rand`, `crypto/rand`, `runtime/debug`, `plugin`, `unsafe`,
  `text/template`, `testing` and cgo are forbidden.
- **pure** — same std restrictions as core, but may use vetted external parsing
  libraries (HCL, k8s API types, YAML) and may hold immutable package-level tables
  (e.g. compiled redaction patterns).
- **io** — may do I/O. Still forbidden: `os/exec` (one exception, see §4.1),
  `unsafe`, `plugin`, `text/template`, `syscall`, `testing`, cgo.
- **entry** — wiring only; same std rules as io.
- **tooling** — repository tooling, never linked into the `clapa` binary.

### 3.2 Dependency table (authoritative)

The table below is **generated** from `internal/archtest/layers.go` by
`task gen` (`go run ./tools/archgen`). The same Go table drives:

1. `internal/archtest` — a test that parses every `.go` file in the module and fails
   on any import not allowed by the table (**authoritative**; covers test files too);
2. the `depguard` rules in `.golangci.yml` (also generated, IDE/CI mirror);
3. the `gochecknoglobals` / `time.Now` scoping in `.golangci.yml` (core packages).

A drift test fails CI if this section or `.golangci.yml` is not what the table
generates. Rules for reading the table:

- "Module imports" are exact packages; `x/...` means `x` and every package below it.
- "External" entries match the module path exactly or as a `path/` prefix
  (`k8s.io/api` does **not** match `k8s.io/apimachinery`).
- Every package in the module must have a row; a new package without a row fails
  `archtest`.
- Test files (`_test.go`) may additionally import: the package under test, the
  row's "test-only" packages, `pgregory.net/rapid`, `github.com/stretchr/testify`,
  `sigs.k8s.io/yaml`, `github.com/santhosh-tekuri/jsonschema`, and any std package
  except `unsafe`, `os/exec`, `plugin`, `text/template` and cgo.
- `internal/arn` is a **leaf**: it imports nothing from the module.

<!-- BEGIN GENERATED: layer-table (task gen) — DO NOT EDIT -->
| Package | Layer | May import (module) | May import (external) | Extra std / test-only |
|---|---|---|---|---|
| `cmd/clapa` | entry | `internal/cli` | — | — |
| `internal/access` | core | `internal/model`, `internal/arn`, `internal/eval`, `internal/eval/match`, `internal/eval/condition`, `internal/graph`, `internal/scoring` | — | tests: `internal/iampolicy` |
| `internal/app` | entry | `internal/config`, `internal/collect/...`, `internal/normalize/...`, `internal/model`, `internal/classify`, `internal/iampolicy`, `internal/eval`, `internal/access`, `internal/graph`, `internal/paths`, `internal/rules`, `internal/rules/catalog`, `internal/scoring`, `internal/findings`, `internal/remediate`, `internal/verify`, `internal/patch`, `internal/report/...`, `internal/llm/...`, `internal/coverage`, `internal/redact`, `internal/safeio`, `internal/version`, `internal/managedpolicies`, `pkg/schema` | `golang.org/x/sync` | tests: `internal/eval/condition`, `internal/eval/match`, `internal/collect/awslive/awsfake` |
| `internal/archtest` | tooling | — (leaf) | — | — |
| `internal/arn` | core | — (leaf) | — | — |
| `internal/classify` | core | `internal/model`, `internal/arn` | — | — |
| `internal/cli` | entry | `internal/app`, `internal/config`, `internal/rules`, `internal/rules/catalog`, `internal/version`, `internal/redact`, `pkg/schema` | `github.com/spf13/cobra` | std: `os/exec`; tests: `internal/collect/awslive`, `internal/collect/awslive/awsfake`, `internal/collect/k8s/live/k8sfake`, `internal/llm` |
| `internal/collect` | io | `internal/coverage`, `internal/safeio` | — | std: `net/url`; tests: `internal/model` |
| `internal/collect/awslive` | io | `internal/collect`, `internal/coverage`, `internal/collect/awsraw` | `github.com/aws/aws-sdk-go-v2`, `github.com/aws/smithy-go`, `golang.org/x/sync` | tests: `internal/collect/awslive/awsfake` |
| `internal/collect/awslive/awsfake` | io | `internal/collect/awslive` | `github.com/aws/aws-sdk-go-v2`, `github.com/aws/smithy-go` | — |
| `internal/collect/awsraw` | pure | `internal/coverage` | `github.com/aws/aws-sdk-go-v2` | — |
| `internal/collect/awssnapshot` | io | `internal/collect`, `internal/coverage`, `internal/safeio`, `internal/collect/awsraw` | `github.com/aws/aws-sdk-go-v2` | — |
| `internal/collect/k8s/live` | io | `internal/collect`, `internal/coverage`, `internal/collect/k8sraw` | `k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/client-go`, `github.com/aws/aws-sdk-go-v2`, `github.com/aws/smithy-go`, `golang.org/x/sync` | tests: `internal/collect/k8s/manifests`, `internal/normalize`, `internal/normalize/k8s`, `internal/safeio`, `internal/model` |
| `internal/collect/k8s/live/k8sfake` | io | `internal/collect/k8s/live` | `k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/client-go` | — |
| `internal/collect/k8s/manifests` | io | `internal/collect`, `internal/coverage`, `internal/safeio`, `internal/collect/k8sraw` | `k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/client-go`, `sigs.k8s.io/yaml`, `go.yaml.in/yaml/v3` | — |
| `internal/collect/k8sraw` | pure | — (leaf) | `k8s.io/api`, `k8s.io/apimachinery` | — |
| `internal/collect/terraform/hclstatic` | io | `internal/collect`, `internal/coverage`, `internal/safeio`, `internal/collect/tfraw` | `github.com/hashicorp/hcl/v2`, `github.com/zclconf/go-cty` | — |
| `internal/collect/terraform/plan` | io | `internal/collect`, `internal/coverage`, `internal/safeio`, `internal/collect/tfraw` | `github.com/hashicorp/terraform-json`, `github.com/hashicorp/hcl/v2` | std: `os/exec` |
| `internal/collect/tfraw` | pure | — (leaf) | `github.com/hashicorp/hcl/v2`, `github.com/hashicorp/terraform-json`, `github.com/zclconf/go-cty` | — |
| `internal/config` | pure | `internal/model`, `internal/arn`, `internal/classify` | `sigs.k8s.io/yaml`, `go.yaml.in/yaml/v3` | — |
| `internal/coverage` | core | — (leaf) | — | — |
| `internal/eval` | core | `internal/model`, `internal/arn`, `internal/eval/match`, `internal/eval/condition` | — | tests: `internal/iampolicy` |
| `internal/eval/condition` | core | `internal/model`, `internal/arn` | — | std: `net/netip` |
| `internal/eval/match` | core | `internal/model`, `internal/arn` | — | — |
| `internal/findings` | core | `internal/model`, `internal/graph`, `internal/paths`, `internal/rules`, `internal/scoring` | — | — |
| `internal/graph` | core | `internal/model`, `internal/eval` | — | — |
| `internal/iampolicy` | core | `internal/model`, `internal/arn` | — | — |
| `internal/llm` | pure | `pkg/schema`, `internal/redact`, `internal/llm/pseudonymize` | — | — |
| `internal/llm/claude` | io | `internal/llm` | `github.com/anthropics/anthropic-sdk-go/v2` | tests: `internal/llm/pseudonymize` |
| `internal/llm/pseudonymize` | pure | — (leaf) | — | — |
| `internal/managedpolicies` | pure | — (leaf) | — | — |
| `internal/model` | core | `internal/arn` | — | — |
| `internal/normalize` | pure | `internal/model`, `internal/arn`, `internal/coverage` | — | — |
| `internal/normalize/aws` | pure | `internal/model`, `internal/arn`, `internal/normalize`, `internal/coverage`, `internal/iampolicy`, `internal/managedpolicies`, `internal/collect/awsraw` | `github.com/aws/aws-sdk-go-v2` | std: `net/url`; tests: `internal/collect`, `internal/collect/awssnapshot`, `internal/safeio` |
| `internal/normalize/k8s` | pure | `internal/model`, `internal/arn`, `internal/normalize`, `internal/coverage`, `internal/collect/k8sraw` | `k8s.io/api`, `k8s.io/apimachinery`, `sigs.k8s.io/yaml` | tests: `internal/collect`, `internal/collect/k8s/manifests`, `internal/safeio` |
| `internal/normalize/terraform` | pure | `internal/model`, `internal/arn`, `internal/normalize`, `internal/coverage`, `internal/iampolicy`, `internal/managedpolicies`, `internal/collect/tfraw` | `github.com/hashicorp/hcl/v2`, `github.com/hashicorp/terraform-json`, `github.com/zclconf/go-cty` | tests: `internal/collect`, `internal/collect/terraform/hclstatic`, `internal/collect/terraform/plan`, `internal/safeio`, `internal/eval`, `internal/eval/match`, `internal/eval/condition` |
| `internal/patch` | pure | `internal/model`, `internal/iampolicy`, `internal/remediate`, `internal/findings` | `github.com/hashicorp/hcl/v2`, `github.com/zclconf/go-cty`, `github.com/aymanbagabas/go-udiff`, `go.yaml.in/yaml/v3` | — |
| `internal/paths` | core | `internal/model`, `internal/graph` | — | tests: `internal/eval` |
| `internal/redact` | pure | — (leaf) | — | std: `log/slog` |
| `internal/remediate` | core | `internal/model`, `internal/arn`, `internal/iampolicy`, `internal/eval`, `internal/graph`, `internal/paths`, `internal/rules`, `internal/findings` | — | — |
| `internal/report` | pure | `pkg/schema`, `internal/model`, `internal/graph`, `internal/paths`, `internal/rules`, `internal/scoring`, `internal/findings`, `internal/coverage`, `internal/version` | — | — |
| `internal/report/console` | pure | `internal/report`, `pkg/schema` | — | — |
| `internal/report/htmlreport` | pure | `internal/report`, `pkg/schema` | `golang.org/x/net/html` | — |
| `internal/report/jsonreport` | pure | `internal/report`, `pkg/schema` | — | — |
| `internal/report/junit` | pure | `internal/report`, `pkg/schema` | — | — |
| `internal/report/markdown` | pure | `internal/report`, `pkg/schema` | — | — |
| `internal/report/sarif` | pure | `internal/report`, `pkg/schema` | — | — |
| `internal/rules` | core | `internal/model`, `internal/arn`, `internal/eval`, `internal/graph`, `internal/paths`, `internal/scoring` | — | — |
| `internal/rules/catalog` | core | `internal/rules`, `internal/rules/pathrules`, `internal/rules/posture`, `internal/rules/escalation` | — | — |
| `internal/rules/escalation` | core | `internal/model`, `internal/arn`, `internal/eval`, `internal/eval/match`, `internal/graph`, `internal/paths`, `internal/rules`, `internal/scoring`, `internal/access` | — | — |
| `internal/rules/pathrules` | core | `internal/model`, `internal/arn`, `internal/eval`, `internal/eval/match`, `internal/graph`, `internal/paths`, `internal/rules`, `internal/scoring`, `internal/access` | — | — |
| `internal/rules/posture` | core | `internal/model`, `internal/arn`, `internal/eval`, `internal/eval/match`, `internal/graph`, `internal/paths`, `internal/rules`, `internal/scoring`, `internal/access` | — | tests: `internal/iampolicy` |
| `internal/safeio` | io | — (leaf) | — | — |
| `internal/scoring` | core | `internal/model`, `internal/eval`, `internal/graph`, `internal/paths` | — | — |
| `internal/verify` | core | `internal/model`, `internal/eval`, `internal/graph`, `internal/access`, `internal/paths`, `internal/rules`, `internal/remediate`, `internal/findings` | — | — |
| `internal/version` | pure | — (leaf) | — | — |
| `pkg/schema` | pure | — (leaf) | — | — |
| `tools/archgen` | tooling | `internal/archtest` | — | — |
| `tools/benchgate` | tooling | — (leaf) | — | — |
| `tools/depage` | tooling | — (leaf) | `golang.org/x/mod`, `go.yaml.in/yaml/v3` | — |
| `tools/refresh-managed-policies` | tooling | — (leaf) | `github.com/aws/aws-sdk-go-v2` | — |

Standard-library packages denied in non-test files, by layer (an entry also denies its subpackages):

| Layer | Denied std packages |
|---|---|
| core | `os`, `net`, `io/fs`, `io/ioutil`, `log`, `syscall`, `math/rand`, `crypto/rand`, `runtime/debug`, `plugin`, `unsafe`, `text/template`, `testing`, `C` |
| pure | `os`, `net`, `io/fs`, `io/ioutil`, `log`, `syscall`, `math/rand`, `crypto/rand`, `runtime/debug`, `plugin`, `unsafe`, `text/template`, `testing`, `C` |
| io | `os/exec`, `syscall`, `plugin`, `unsafe`, `text/template`, `testing`, `C` |
| entry | `os/exec`, `syscall`, `plugin`, `unsafe`, `text/template`, `testing`, `C` |
| tooling | `os/exec`, `syscall`, `plugin`, `unsafe`, `text/template`, `testing`, `C` |
<!-- END GENERATED: layer-table -->

**Decision — `go/parser` instead of `go/packages` for archtest.** `go/packages`
shells out to `go list` and applies build constraints for one GOOS/GOARCH. Parsing
every file with `go/parser` (imports only) checks *all* platform variants at once,
needs no external dependency and no subprocess. Trade-off: no type information —
not needed for import rules.

**Flag — depguard semantics.** depguard v2 allow/deny entries are prefix matches;
we generate `pkg$` (exact) and `pkg/` (descendants) pairs to avoid
`k8s.io/api` ⊂ `k8s.io/apimachinery` false allows, and use `!$test` so depguard
checks only non-test files. depguard's behaviour when an import matches both an allow
(`$gostd`) and a deny entry is verified empirically in Phase 1 (see the Phase 1
report); `archtest` remains authoritative regardless.

### 3.3 Go conventions

- Go: `go 1.26.0` in `go.mod` (oldest of the two latest stable releases, verified
  2026-11-20: go1.27.4 and go1.26.11). CI matrix: 1.26.x and 1.27.x × Linux, macOS,
  Windows.
- `context.Context` is the first parameter of every collector method and every
  operation that may block or run long.
- Errors: wrapped with `%w`; sentinel errors (`var ErrX = errors.New(...)`) or typed
  errors for anything a caller branches on. No `panic` in library code; `recover`
  only in `cmd/clapa`, mapped to exit code 4.
- Canonical model types: unexported fields + constructors (or small value types);
  constructors copy input slices; getters return copies or read-only views;
  collections sorted by canonical ID wherever order can reach output.
- Logging: `log/slog` only in io/entry layers; core returns data, never logs.
- Limits, enforced by `archtest` and `revive`: no `.go` file over 400 lines;
  functions ≤ 50 statements / 80 lines; cyclomatic complexity ≤ 15; cognitive
  complexity ≤ 20. A function does one pipeline stage.

### 3.4 Determinism

Same inputs ⇒ byte-identical JSON (spec §11.4). Mechanisms:

- No map iteration reaches output; maps are converted to slices sorted by a total
  order (canonical ID, then a tiebreak on every remaining field).
- All scores are **integers in fixed point** (per-mille), see `docs/SCORING.md`.
  Rationale: Go permits fused multiply-add on some architectures (e.g. arm64), so
  float results can differ across platforms.
- No timestamps, durations or absolute paths in output unless `--timestamps`
  (timing data is gated by the same flag — **Flag**: the spec asks for "timing" in
  JSON *and* byte-identical output; we keep timing behind `--timestamps`).
- Input paths are reported relative to the scan root with `/` separators.
- `.gitattributes` forces LF line endings so fixtures and goldens are identical on
  Windows.
- A test runs every golden scan twice (and with shuffled input order) and compares
  bytes.

---

## 4. Ingestion

All collectors implement:

```go
type Collector interface {
    Name() string
    Collect(ctx context.Context, in Input, gaps *coverage.Recorder) (Bundle, error)
}
```

Collectors return **raw** provider types (`tfraw`, `k8sraw`, `awsraw`), never
canonical model types. Every read goes through `internal/safeio`: size cap (default
16 MiB per file, configurable), JSON/YAML nesting depth cap (default 64), refusal to
follow symlinks out of the scan root, and regular files only.

### 4.1 Terraform

**Plan JSON (primary).** `terraform show -json <planfile>` output, parsed with
`hashicorp/terraform-json`. Resolves modules, `for_each`, `count`, variables,
locals, data sources. Values "known after apply" (e.g. a new role's ARN) become
symbolic references (`tfref{address, attribute}`) — **never** guessed strings.

**Decision — the one `os/exec`.** If the user passes a binary plan *file* (not JSON),
`collect/terraform/plan` runs `terraform show -json <file>` with an argument slice
(no shell), a timeout, a stdout size cap and a scrubbed environment. The binary is
resolved with `exec.LookPath` (which since Go 1.19 refuses results relative to the
current directory) or an explicit `--terraform-bin`. This is the only package
allowed to import `os/exec` (enforced by the table).

**Static HCL (secondary).** `hcl/v2` + `hclsyntax`. An `hcl.EvalContext` built from
`variables.tf` defaults, `*.tfvars`, `*.auto.tfvars`, `locals`, and the function
whitelist `jsonencode, format, concat, merge, lookup, join, replace, lower, upper,
tostring, tolist, toset` taken from `go-cty`'s `function/stdlib` — nothing else
is callable. Resource attribute references become symbolic references linked by the
normalizer. Anything else becomes `Unresolved{Expr, Range}` (with the `hcl.Range`),
never a guess, never dropped. Findings depending on an `Unresolved` value get
`confidence: low` and the value is listed in the coverage section.

Policy documents in every form: `jsonencode(...)`, heredoc JSON,
`data "aws_iam_policy_document"` (incl. `principals`, `condition`, `not_actions`,
`not_resources`, `source_policy_documents`/`override_policy_documents`), inline
role policies, `aws_iam_role_policy_attachment`, `aws_iam_policy_attachment`,
`managed_policy_arns`, `permissions_boundary`.

**AWS managed policies** resolve by ARN from a vendored, versioned snapshot embedded
in `internal/managedpolicies` (with snapshot date and source). `tools/refresh-managed-policies`
regenerates it from `iam:ListPolicies(Scope=AWS)` + `iam:GetPolicyVersion`. An
attached managed policy that is not in the snapshot is an explicit coverage gap.

### 4.2 Kubernetes

Manifests (multi-doc YAML, Helm-rendered and Kustomize-built output — CLAPA never
runs `helm`/`kustomize`) are decoded with client-go's universal deserializer into
`k8s.io/api` types, so field semantics match the API server.

**Decision — line numbers.** The deserializer loses positions, so each document is
also parsed with `sigs.k8s.io/yaml/goyaml.v3` into a `yaml.Node` tree to map objects
(and selected fields) to `file:line`. Unknown kinds or fields are warnings with
`file:line`, never fatal.

Kinds: Deployment, StatefulSet, DaemonSet, Job, CronJob, Pod, ReplicaSet,
ServiceAccount, Role, ClusterRole, RoleBinding, ClusterRoleBinding, NetworkPolicy,
Service (`LoadBalancer`/`NodePort`), Ingress, Namespace, the `aws-auth` ConfigMap.

Workload identity:

- **IRSA**: `eks.amazonaws.com/role-arn` on the ServiceAccount. The trust policy is
  evaluated with `sts:AssumeRoleWithWebIdentity`, principal `Federated = <OIDC
  provider ARN>`, context `<issuer>:sub = system:serviceaccount:<ns>:<sa>` and
  `<issuer>:aud = sts.amazonaws.com`. **Flag**: the audience can be changed with the
  `eks.amazonaws.com/audience` annotation (EKS User Guide › "Configure Kubernetes
  service accounts to assume an IAM role"); we read it, and default to
  `sts.amazonaws.com` only when absent, recording that assumption.
- **EKS Pod Identity**: associations (cluster, namespace, service account → role).
  Trust evaluated with principal `Service = pods.eks.amazonaws.com`, actions
  `sts:AssumeRole` and `sts:TagSession` (EKS User Guide › "EKS Pod Identity").
- **Node instance role via IMDS** — `NODE_ROLE` edge with an explicit precondition:
  reachable when `hostNetwork: true`, **or** IMDSv1 is allowed (`HttpTokens=optional`),
  **or** `HttpPutResponseHopLimit ≥ 2` (IMDSv2 from a pod needs one extra hop) — and
  `HttpEndpoint` is enabled. **Flag**: IMDS settings often live in launch templates
  not present in the input; then the precondition is UNKNOWN and the edge gets
  `confidence: low` (EC2 User Guide › "Configure the instance metadata options").
  NetworkPolicy egress rules that block `169.254.169.254/32` are honoured when the
  CNI enforces NetworkPolicy; whether it does is a config assumption.
- **Default ServiceAccount** — modelled like any other SA; pods without
  `serviceAccountName` run as `default`.

### 4.3 AWS offline snapshots

`clapa collect-snapshot --out DIR` writes a bundle (format `clapa-snapshot/v1`)
and `clapa scan --aws-snapshot DIR` reads it. Live collection and the snapshot of
the same account produce the same raw data, gaps and notes
(`TestWriteThenCollectRoundTrips`, `TestCollectSnapshotThenScanMatchesLive`).
Files are named after the API call and hold its JSON, as the AWS CLI prints it:

```
manifest.json                       format, accounts, and every API call with its outcome
<account>/iam/get-account-authorization-details.json
<account>/s3/<bucket>/{get-bucket-location,get-bucket-policy,get-bucket-encryption,
                       get-public-access-block,get-bucket-tagging}.json
<account>/<region>/kms/list-aliases.json
<account>/<region>/kms/<key-id>/{describe-key,get-key-policy,get-key-rotation-status,list-resource-tags}.json
<account>/<region>/eks/<cluster>/describe-cluster.json
<account>/<region>/eks/<cluster>/pod-identity/<association-id>.json
<account>/<region>/secretsmanager/<secret-name>/{describe-secret,get-resource-policy}.json
<account>/<region>/ssm/<parameter-name>/{describe-parameters,list-tags-for-resource,get-resource-policies}.json
```

A file is missing when the answer was "none", for example a bucket without a
policy. A call that failed is recorded in the manifest. The reader takes a
resource policy whose call failed as **unknown**, never as absent. Names
are escaped into one path component:

- an upper-case letter becomes `!x`;
- every other byte outside `[a-z0-9_+=@.-]`, and a leading `.`, becomes `%XX`.

AWS names are case-sensitive, but Windows and macOS file systems usually are
not, so two names that differ only in case never share a file. The writer
creates a new directory through `os.Root`, so no name can place a file outside
it. The output is deterministic.

### 4.4 Live AWS

Read-only (`internal/collect/awslive`). `docs/PERMISSIONS.md` lists the minimal
policy, and tests keep it identical to the calls the code makes. The
`SecurityAudit` + `ViewOnlyAccess` expectation is not verified until the
managed-policy snapshot is refreshed (§12.1).

Collected:

- STS: identifies the account.
- IAM: `GetAccountAuthorizationDetails`, every page.
- S3: every bucket's location, policy, default encryption, Block Public Access
  and tags, read from a client in the bucket's region; the account's Block
  Public Access (`s3control GetPublicAccessBlock`, IAM action
  `s3:GetAccountPublicAccessBlock`; Phase 7). No configuration is every setting
  off; a failed call is unknown.
- KMS, per region: keys and aliases; for each key its metadata and key policy,
  and for customer managed keys their rotation and tags.
- EKS: clusters (OIDC issuer) and Pod Identity associations.
- Secrets Manager and SSM: metadata and resource policies, **never a value**.
  The client interfaces are read-only by test, and a test fails if the
  collector's source names a value read.

Mechanics:

- SDK paginators everywhere.
- `retry.NewAdaptiveMode`.
- A timeout per call (each page of a list).
- `errgroup.SetLimit` per service and region.
- Several regions (`--aws-region`, repeatable; the default is the profile's
  region).
- Several accounts with `sts:AssumeRole` (`--aws-assume-role`, repeatable).
  Enumerating accounts through AWS Organizations is not built.

**Partial failure is first-class.** Every call is recorded with its outcome in
`awsraw.Call`; `manifest.json` lists the same calls in a snapshot.

- A failed call is a coverage gap. Live and snapshot data map calls to gaps the
  same way (`awsraw.Call.Gap`).
- A resource policy whose call failed is **unknown**, never "no policy".
- Per service and region, coverage is computed from the calls
  (`awsraw.ServiceCoverage`): the units are the items the list call returned,
  and complete units are those with no failed call. A list call that failed or
  was not made leaves the size unknown. The console prints every incomplete or
  unknown coverage as a warning.
- Nothing collected is exit 3.
- Every live or snapshot report lists the attached AWS managed policies missing
  from the vendored snapshot (count and names). The console warns:
  "managed policy snapshot is incomplete: run tools/refresh-managed-policies".
  An UNKNOWN that comes from such a policy names it in `undecided`.

Not collected, and stated in every live or snapshot report:

- (since Phase 7, nothing here: the account-level S3 Block Public Access is
  collected. A snapshot written before Phase 7 has none; each such account gets
  a `not-modelled` note, and its buckets keep their own setting.)

Tests run against fakes (`awsfake`), against the SDK's own clients over
in-memory HTTP stubs (pagination, AccessDenied, throttling with retries), and
against LocalStack in `integration.yml`. LocalStack images from 2026.03 on
require an account token, so the job pins 4.14.0, the last image without one,
by digest. LocalStack's free services do not include EKS, so EKS is covered by
the fakes and stubs only. No test reaches AWS: the integration test refuses an
endpoint that is not on the runner.

### 4.5 Live Kubernetes

`client-go` only (`internal/collect/k8s/live`):

- **Kinds:** every kind §4.2 analyses is listed across namespaces with
  `Limit`/`Continue`. A list that fails, even part-way, keeps nothing of that
  kind and is a coverage gap.
- **Secrets:** listed as **metadata only** (`PartialObjectMetadataList`: the
  API server never sends their data).
- **ConfigMaps:** only `kube-system/aws-auth` is read.
- **Owned objects:** those a workload controller owns are skipped, since the
  owner's template is analysed, as in a manifest scan. Objects owned by any
  other controller (a custom resource, for example) are kept.

Connections:

- `--live-k8s CONTEXT[=CLUSTER]`: a kubeconfig context, non-interactive, TLS
  verified.
- `--k8s-eks NAME`: an in-memory token, a SigV4-presigned
  `sts:GetCallerIdentity` that signs `x-k8s-aws-id`, renewed before it expires.
  The endpoint, CA and ARN come from `eks:DescribeCluster`.
- **Credential plugins are refused.** A kubeconfig user that runs an exec (or
  auth-provider) credential plugin is refused, since CLAPA runs no external
  commands. The error names the context, says why, and gives the alternatives:
  `--k8s-eks NAME` for EKS, or a kubeconfig with a static token or a client
  certificate otherwise.
- **`--insecure`:** turns TLS verification off for the `--live-k8s` clusters.
  This is warned on stderr and recorded in the report.
- Tokens are never logged.

Tests:

- **Fake API servers:** lists, pages, part-way failures, forbidden lists,
  nothing listed.
- **The EKS token:** built offline with the real STS presigner.
- **Manifests vs live:** every scenario's manifests, served by a fake API
  server and collected live, normalize to the manifest scan's inventory.
- **A kind cluster** (`integration.yml`; kind v0.33.0, node v1.37.0, pinned by
  digest). Scenario manifests are applied, then read as a service account bound
  to exactly the ClusterRole of `docs/PERMISSIONS.md`. The test expects no
  access-denied gap, every manifest object collected the same, and a Secret
  received without its data.

### 4.6 Decisions made while implementing (Phase 3)

| Topic | Decision | Why / source |
|---|---|---|
| Unresolved values reach the evaluator | Every value a collector cannot resolve becomes `${clapa:unresolved:<id>}` inside policy documents. The evaluator treats it as **UNKNOWN** in Action, Resource, Principal (including the caller's own identity), condition keys and values, in every policy version | your Phase 3 instruction; never text, never a guess (corpus file 18) |
| Policy content not available at all | represented by an unknown Allow **and** an unknown Deny, so it can never produce ALLOW and can never hide a deny | an absent policy is not evidence of "no permissions" |
| Plan values known only after apply | a plain attribute reference becomes symbolic (`aws_kms_key.pii.arn`); a computed expression becomes `unknown-after-apply` and a gap. Note: `jsonencode(...)` over an unknown value makes the whole attribute unknown in plan JSON; static mode keeps its structure | terraform-json `after_unknown` + configuration references |
| Plan file positions | plan JSON has no line numbers; plan evidence names the plan file and the resource address. Line-level evidence comes from static mode (Phase 4 may join them) | terraform-json format |
| Static HCL roots | every directory with `.tf` files is its own root module; `module` calls, `count`/`for_each` and `dynamic` blocks are not expanded and are reported. Only `terraform.tfvars` and `*.auto.tfvars` are loaded, as Terraform does | Terraform › Input variables › "Variable definitions files" |
| Values AWS generates at apply | only a value **no policy can name literally** (a KMS key ID, the name of a bucket or role created without any name) gets a deterministic pending ID: `…:key/tf-<address>`, `arn:aws:s3:::tf-<address>`; a secret's random suffix is `-tfpend` | needed to evaluate policies before apply |
| Unknown account, region or name (**corrected after Phase 3 review**) | every unknown ARN segment carries an unresolved placeholder: `${clapa:unresolved:account_of_<root>}`, `…region_of_<root>}`, a name `"${var.env}-pii"` stays `<placeholder>-pii`, a `name_prefix`/`bucket_prefix` becomes `prefix<placeholder>`. The first version used `""` (a literal empty segment) and the pending ID for unresolved names, so `Resource = "arn:aws:s3:::prod-pii/*"` gave a definite IMPLICIT_DENY and a real path was lost silently. Each unknown account/region is still a coverage gap | review finding; nothing turns gaps into UNKNOWN later, so the placeholder itself must carry it |
| Matching a partly unknown request value | `match.Value`: False only when **no** substitution of the unknown parts can match (pattern intersection, `arn.Pattern.Intersects`), True when the pattern matches whatever they are, otherwise UNKNOWN. An unknown account on either side makes same- vs cross-account UNKNOWN; an unresolved request value in a condition is UNKNOWN | evaluator, corpus file 18 |
| End-to-end proof | `internal/normalize/terraform/unknown_parts_test.go`, from HCL through the normalizer to the evaluator: (a) bucket `"${var.env}-pii"` vs `arn:aws:s3:::prod-pii/*` → UNKNOWN; (b) unknown account vs `arn:aws:kms:us-east-1:111122223333:key/*` → UNKNOWN; (c) unknown account vs a bucket policy naming `arn:aws:iam::111122223333:role/app` → UNKNOWN; (d) with `env` set, or the account set in options: `prod`/`111122223333` → ALLOW, `dev`/`999999999999` → IMPLICIT_DENY | your Phase 3 review |
| Instance references in a real plan (**found with real Terraform output, Phase 3 review**) | `terraform show -json` records `aws_iam_role.r[each.key].id` only as `["aws_iam_role.r", "each.key"]`: no attribute, no key. `each.key` and `count.index` name the referencing instance's own key, so the reference resolves exactly to `…aws_iam_role.r["etl"]`. `each.value` equals the key when the `for_each` source is a set ("If a set was provided, this is the same as `each.key`", Terraform › The `for_each` Meta-Argument). **The plan cannot show that**: `toset(var.names)` and `{ for n in var.names : n => upper(n) }` are both recorded as `for_each_expression {"references": ["var.names"]}` with the same instance keys, and plan JSON carries no variable types (checked with real output). So the set is verified in the configuration the plan was made from, when given (`plan.Options.ConfigDir`; the fixtures pass their `terraform/`): the `for_each` expression is `toset(...)`, or a variable declared `type = set(...)`; only local module sources are followed, nothing is evaluated, files are read through `safeio` inside the scan root. Any other selector, a map or comprehension, or no configuration: the policy is attached to **every** instance of the resource, each copy with an extra condition on an unresolved key, so every Allow and Deny there is UNKNOWN — never ALLOW for one instance and IMPLICIT_DENY for the others, never dropped — plus a gap that says why. Limitation: the references cannot tell `r[each.key]` from `r[upper(each.key)]`; the plan has no expression text | Terraform 1.17.1 output: scenario 13 (`each.value` over `toset`), `internal/collect/terraform/plan/testdata/for_each_key` and `for_each_map` (a map comprehension: UNKNOWN by design); `TestForEachInstanceReferences`, `TestForEachSetSources`, `TestForEachRoleSelection`, `TestForEachKeyAndValueAgree` (both forms give the same roles and attachments) |
| Provider-computed attributes | an attribute marked unknown in `after_unknown` that the configuration does not set is computed by the provider (`Reason: computed`). Unset `inline_policy` and `managed_policy_arns` of `aws_iam_role` add nothing ("If this attribute is not configured, Terraform will ignore policy attachments to this resource"); set but unknown (or a `dynamic` block in static mode) gives an unknown policy. Other computed attributes (`arn`, `id`) stay unknown and are gaps; the Phase 5 coverage tolerance must not count gaps that no decision used | AWS provider › `aws_iam_role` (argument reference, `managed_policy_arns`/`inline_policy`); `TestComputedPolicyAttributes` |
| EKS Pod Identity (**built after the Phase 3 review**) | an association links a service account (cluster, namespace, name) to a role. `access.PodIdentityAssume` evaluates the role's trust policy through the evaluator for **both** `sts:AssumeRole` and `sts:TagSession` by `pods.eks.amazonaws.com`, with the request tags EKS adds: `aws:RequestTag/eks-cluster-arn` (unknown when the cluster ARN is not in the input), `…/eks-cluster-name`, `…/kubernetes-namespace`, `…/kubernetes-service-account` known; `…/kubernetes-pod-name` and `…/kubernetes-pod-uid` unknown; `aws:TagKeys` and `sts:TransitiveTagKeys` = the six keys; every other key (e.g. `aws:SourceAccount`, not documented for Pod Identity) unknown. ALLOW needs AssumeRole ALLOW, TagSession ALLOW unless `disable_session_tags` (default false; unknown in a snapshot that does not record it), and the `eks-pod-identity-agent` add-on in the input — its absence from the input is UNKNOWN, not "missing". `target_role_arn` is recorded; the chain into it is an ordinary role-chain edge (Phase 4). Not modelled: Fargate/Windows nodes (unsupported by Pod Identity), credentials earlier in the SDK chain overriding Pod Identity | EKS User Guide › "EKS Pod Identity", "Create the role" (trust policy), "Grant pods access to AWS resources based on tags" (six transitive session tags); IAM User Guide › "Passing session tags in AWS STS" ("the AssumeRole operation fails" without `sts:TagSession`); EKS API › `CreatePodIdentityAssociation` (`targetRoleArn`, `disableSessionTags`); `internal/access/podidentity_test.go` (16 cases), scenario 17 |
| Reserved placeholder text in input (**fixed after the Phase 3 review**) | only the normalizer creates `${clapa:unresolved:…}`. Two layers: **(1) rejection at input** — any decoded input string containing the prefix is invalid input, reported as a `parse-error` gap with file:line and treated as an ordinary unknown value: Terraform values, object keys and template literals after HCL decoding (`$$` and backslash-u escapes), templates whose input pieces assemble the prefix around a reference, plan JSON values and keys, JSON escapes inside a policy string (`iampolicy.ErrReservedText`: a document may hold only placeholders its caller wrote as plain text), Kubernetes YAML scalars after YAML decoding (backslash-x and backslash-u escapes; the document is not loaded), snapshot JSON files including policy documents embedded as JSON strings or URL-encoded (up to 3 levels; the file is not loaded), and `clapa.yaml` (configuration error). **(2) registry** — `normalize.Builder.Placeholder` registers each placeholder it hands out; `Build` fails with `ErrUnregisteredPlaceholder` if any inventory string holds another (fail closed) | your Phase 3 review; `internal/app/reserved_test.go` (every channel), `internal/collect/reserved_test.go`, `TestReservedText` (parser), `internal/normalize/placeholders_test.go` (registry, all inventory fields), fuzz `FuzzReservedText` and the `FuzzParse` properties |
| S3 default encryption | a bucket without an encryption configuration in Terraform is SSE-S3; in a snapshot without `get-bucket-encryption`, it is unknown | S3 User Guide › "Default encryption" (all new objects since January 2023) |
| KMS key without `policy` | the documented default key policy (account root, `kms:*`) | KMS Developer Guide › "Default key policy" |
| AWS managed policies | resolved from the vendored snapshot (`internal/managedpolicies`, 3 policies checked against the AWS Managed Policy Reference on 2026-11-20; refresh with `tools/refresh-managed-policies`). Any other managed policy is unknown and a gap. **Known constraint: must be expanded before Phase 6** (section 12.1) | spec §4.1 |
| `aws_iam_policy_document` with `source_policy_documents`/`override_*` | not merged; the rendered document gets unknown statements, added where it is parsed (as a resource or identity policy) | merging rules are not modelled yet |
| IRSA request | principal = `oidc-provider/<issuer>` in the role's account; context `<issuer>:sub = system:serviceaccount:<ns>:<name>` and `<issuer>:aud` (annotation or `sts.amazonaws.com`); every other key unknown. No issuer → unresolved provider ARN → UNKNOWN. The trust policy is always decided by the evaluator (`access.IRSARequest`, `internal/app/irsa_test.go` on scenarios 1, 4, 5) | your Phase 3 instruction; EKS User Guide › IRSA |
| Implicit `default` service account | added for every namespace whose workloads use it without a manifest (Kubernetes creates it) | Kubernetes › Service accounts |
| LoadBalancer exposure | explicit scheme annotation decides; AWS LB Controller types (`external`, `nlb-ip`) default to internal; otherwise the in-tree provider's internet-facing default. NodePort and Ingress without a scheme annotation are `unknown` public | AWS Load Balancer Controller › annotations |
| RBAC | bindings resolved to rules; only `cluster-admin` of the built-in roles is modelled; missing or aggregated roles give grants with unknown rules (and a gap), never dropped | Kubernetes › RBAC › user-facing roles |
| IMDS settings | from the node group's launch template `metadata_options`; without one they are unknown (EKS defaults are not assumed) | EC2 User Guide › instance metadata options |
| Model records | nodes (Principal, Resource, Workload) are immutable types; relation records (ServiceAccount, Cluster, RBACGrant, …) are value types built once by normalizers and sorted by `normalize.Builder.Build` | spec §3.1 allows either |

---

### 4.7 Documented defaults (decided in the Phase 4 review)

A setting the input does not state takes its **documented, deterministic**
default. The node lists the default's key (`model.DocumentedDefaults`) in its
`Defaulted` settings, and every finding that relies on it shows
`value_source: default` with the reference below. Each row was read on its page
on 2026-11-20 and has a test in `internal/app/defaults_test.go`
(`TestEveryDefaultIsTested` fails when a row has none).

| Key | Setting not stated | Value | Documentation |
|---|---|---|---|
| `k8s.automountServiceAccountToken` | Pod and ServiceAccount `automountServiceAccountToken` (the Pod's value wins) | `true` | Kubernetes › Service Accounts: "By default, Kubernetes provides the Pod with the credentials for an assigned ServiceAccount" — https://kubernetes.io/docs/concepts/security/service-accounts/ |
| `k8s.hostNetwork` | PodSpec `hostNetwork` | `false` | Pod API reference: "Host networking requested for this pod. […] Default to false." — https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/ |
| `k8s.securityContext.privileged` | container `securityContext.privileged` | `false` | Pod API reference: "Run container in privileged mode. […] Defaults to false." (same page) |
| `eks.irsa.audience` | ServiceAccount annotation `eks.amazonaws.com/audience` | `sts.amazonaws.com` | EKS Pod Identity Webhook: "optional: Defaults to "sts.amazonaws.com" if not set" — https://github.com/aws/amazon-eks-pod-identity-webhook (the EKS User Guide does not state it) |
| `terraform.aws_kms_key.enable_key_rotation` | Terraform `aws_kms_key` `enable_key_rotation` | `false` | AWS provider › aws_kms_key: "Whether key rotation is enabled. Defaults to `false`." — https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key |
| `kms.default-key-policy` | KMS key created without a key policy | default key policy (account root, `kms:*`) | KMS Developer Guide: "AWS KMS applies a very simple default key policy." — https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html |
| `s3.default-encryption` | S3 bucket without a default encryption configuration | SSE-S3 (`AES256`) | S3 User Guide: SSE-S3 is "the base level of encryption for every bucket"; "Starting January 5, 2023, all new object uploads to Amazon S3 are automatically encrypted" — https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html |
| `s3.block-public-access.new-bucket` | S3 Block Public Access of a bucket a **Terraform plan creates** (`resource_changes` action `create`) with no `aws_s3_bucket_public_access_block` | all four settings on (`restrict_public_buckets = true`) | AWS News Blog › "Heads-Up: Amazon S3 Security Changes Are Coming in April of 2023" (13 Dec 2022; its update of 27 Apr 2023 says the change is in effect for all new buckets in all Regions): newly created buckets "[…] will by default have S3 Block Public Access enabled", including those created with the S3 API, the CLI, the SDKs or CloudFormation (Terraform creates buckets through the S3 API) — https://aws.amazon.com/blogs/aws/heads-up-amazon-s3-security-changes-are-coming-in-april-of-2023/ . The S3 User Guide states the default without a date: "By default, all four Block Public Access settings are enabled." (Creating a general purpose bucket › Using the S3 console) — https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-bucket-overview.html . The User Guide pages read on 2026-11-21 do not state the April 2023 date; its FAQ page (create-bucket-faq.html) now redirects to the S3 welcome page. |
| `eks.pod-identity.disableSessionTags` | Pod Identity association `disableSessionTags` | `false` | EKS API › CreatePodIdentityAssociation — https://docs.aws.amazon.com/eks/latest/APIReference/API_CreatePodIdentityAssociation.html |
| `kms.aws-managed-key.rotation` | rotation of an AWS managed KMS key (`KeyManager: AWS`), not collected | `true` (every year) | KMS Developer Guide › "Rotate AWS KMS keys": "AWS KMS automatically rotates AWS managed keys every year"; "You cannot enable or disable key rotation for AWS managed keys." — https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html (read 2026-11-21) |
| `secretsmanager.aws-managed-key` | a secret encrypted with the AWS managed key `aws/secretsmanager` | principals of the secret's account may decrypt through Secrets Manager; no other account | Secrets Manager User Guide › "Secret encryption and decryption": the key policy allows use "only when Secrets Manager makes the request on the user's behalf" (`kms:ViaService`, `kms:CallerAccount`); "AWS managed keys do not support cross-account access" — https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html (read 2026-11-21) |
| `ssm.aws-managed-key` | a SecureString encrypted with the AWS managed key `aws/ssm` | every IAM principal of the parameter's account may decrypt; no other account | Systems Manager User Guide: "The default AWS KMS key has Decrypt permission for all IAM principals within the AWS account" — https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-access.html ; "AWS managed keys cannot be shared" — https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-shared-parameters.html (read 2026-11-21) |
| `terraform.aws_iam_role.managed_policy_arns` | Terraform `aws_iam_role` `managed_policy_arns` / `inline_policy` not configured | no attachments added | AWS provider › aws_iam_role: "If this attribute is not configured, Terraform will ignore policy attachments to this resource." — https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role |

**No deterministic default — unknown, and a coverage gap:**

| Setting | Why |
|---|---|
| Node IMDS `http_tokens` without launch-template `metadata_options` | the effective value comes from the launch template, then the account default, then the AMI's `imds-support`; without any of them the baseline is "V1 or V2 (token optional)" (EC2 User Guide › Configure instance metadata options), so it depends on inputs CLAPA does not see |
| S3 bucket Block Public Access without `aws_s3_bucket_public_access_block`, for a bucket a plan does **not** create (it already exists), or read statically or from a snapshot | an existing bucket's settings may have been changed after it was created, outside the input; only a bucket the plan creates has the new-bucket default (row above). A fixture that needs the setting states it (the Phase 5 review: declare it rather than raise the gap tolerance) |
| KMS rotation of a key in a snapshot without `kms:GetKeyRotationStatus` | the API value was not collected; the KMS guide only says automatic rotation "is optional" |
| `hostNetwork` / `privileged` stated `false` vs omitted | indistinguishable in the typed Kubernetes API and equal in value; neither marks the node as defaulted, since no rule fires on `false` |

## 5. Canonical model

Types: `Principal` (kinds: IAMRole, IAMUser, AssumedRoleSession, FederatedSession,
K8sServiceAccount, K8sUser, K8sGroup, AWSService, Anonymous/Public, AccountRoot),
`Workload`, `Resource` (`kind`, `arn`, `account`, `region`, `tags`,
`data_classification`, `AuthzTraits`), `PolicyDocument`, `Statement`, `Condition`,
`TrustRelationship`, `NetworkExposure`, `SourceLocation` (file + line range +
resource address, or ARN + API call for live data).

**Stable IDs.** `ID = sha256("clapa/v1\x00" + kind + "\x00" + canonicalIdentity)`,
hex-encoded (64 chars; reports may abbreviate for display only). Canonical
identities:

- AWS: full ARN including partition and account (S3 bucket ARNs carry no account,
  which is fine: names are unique per partition).
- Kubernetes: `k8s:{cluster key}/{namespace}/{kind}/{name}`. The cluster key
  (`model.ClusterKey`) is the cluster's **ARN** when its account and region are
  known (`arn:<partition>:eks:<region>:<account>:cluster/<name>`). Otherwise it
  is the name the user gives (`--k8s DIR=CLUSTER`, `--live-k8s CONTEXT=CLUSTER`).
  Kubernetes input that names no cluster, with none in `clapa.yaml`, uses
  `default` (`model.DefaultClusterName`).
- **Every producer uses the same key** (Phase 6), so cross-layer joins hold:
  - Terraform references by `cluster_name`, in the resource's account and
    region;
  - the AWS collectors (`DescribeCluster`, Pod Identity associations);
  - `clapa.yaml` clusters;
  - manifests and live clusters.
- **Two clusters of one name** in two regions or accounts are two clusters:
  their objects never collide and no edge joins them (scenario 18).
- **Resolving a name.** A Kubernetes input names its cluster by ARN or by name.
  A name resolves against `clapa.yaml`, Terraform and AWS (in that load order),
  and must match one cluster. A name matching several clusters is a
  configuration error (exit 2) that lists their ARNs, never a guess. A name
  nothing describes is its own key. `clapa.yaml` may keep writing
  `k8s:<name>/...` principals: they resolve the same way.
- Terraform resources with an unknown ARN: `tf:{root-module-digest}/{provider-config}/{address}`;
  the normalizer links them to ARN nodes when the ARN becomes known.

**Duplicates are errors.** Two definitions with the same canonical identity fail the
normalize stage with both `SourceLocation`s. **Flag**: scanning Terraform *and* a
live snapshot of the same account yields legitimate duplicates. Safer option for
MVP: error, and advise scanning one source of truth per account. A future
`--merge-sources` mode would need explicit precedence rules.

**Crown jewels** come from (a) classification tags (configurable keys and values,
default `DataClass ∈ {pii, pci, phi, secret}`), (b) explicit config entries, or
(c) the default heuristic (KMS keys, buckets, secrets and SecureString parameters
tagged sensitive). Each crown jewel records **which** of these marked it.

**Entry points**: workloads exposed via `Service` `LoadBalancer`/`NodePort` or
`Ingress`; plus every workload under the "assume any pod compromised" threat model
(`--assume-compromised`, default **on**; the report states which model was used).

---

## 6. Policy evaluator

```go
func Evaluate(req Request, policies PolicySet) Decision
```

`Request` = principal + action + resource + context. `PolicySet` = identity,
resource, permission boundary, SCPs, RCPs and session policies. `Decision` ∈
{`ALLOW`, `DENY`, `IMPLICIT_DENY`, `UNKNOWN`} with the contributing statements
(policy, `Sid` or index, `SourceLocation`) and the unresolved conditions.

### 6.1 Evaluation logic — corrected against the AWS documentation

The spec's precedence list (§6.1) is a simplification. We implement the documented
flow instead (IAM User Guide › "Policy evaluation logic" › "How AWS enforcement code
logic evaluates requests to allow or deny access" and "Policy evaluation for requests
within a single account"):

1. **Explicit deny** in any applicable policy ⇒ `DENY`.
2. **RCPs** (resource control policies, AWS Organizations User Guide › "Resource
   control policies") — if present and the resource's account is under them, they
   must allow. **SCPs** — if present, the principal's account must be allowed.
   (RCPs are not in the spec; they are part of AWS's current logic, so the model
   accepts them. Absent input = "not modelled", recorded as an assumption.)
3. **Resource-based policy** — whether a same-account resource-policy allow is
   sufficient on its own **depends on the principal type it names** (next table).
4. **Identity-based policy** must allow (unless step 3 already decided).
5. **Permissions boundary** — if present, must allow.
6. **Session policy** — if present, must allow.

Same-account effect of a resource-based policy that allows the request, by the
principal named in it (IAM User Guide › "Permissions boundaries for IAM entities" ›
"Evaluating effective permissions with boundaries" › "Resource-based policies"):

| Principal named in the resource-based policy | Implicit deny in identity policy | Implicit deny in permissions boundary | Implicit deny in session policy |
|---|---|---|---|
| **IAM user ARN** | does not limit | does not limit | n/a |
| **IAM role ARN** | does not limit | **limits** | **limits** |
| **Role session ARN** (`arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION`) | does not limit | does not limit | does not limit |
| **IAM user ARN that created a federated user session** (request made by the federated session) | — | **limits** | **limits** |

Notes:

- Explicit denies always win; SCPs and RCPs apply in every row.
- A resource policy naming the **account** (`arn:aws:iam::ACCOUNT:root` or
  `"AWS": "ACCOUNT"`) delegates to IAM: the identity side must allow.
- The spec's statement "a resource policy grant to a role ARN can suffice on its own"
  (§6.1) is therefore only half right: it bypasses the identity policy but **not** a
  permissions boundary or session policy. An earlier draft of the plan had the
  role-ARN row inverted; it was corrected in plan review and this table is the
  design of record.
- **Phase 2 commitment:** the first four cases in `internal/eval/testdata/eval/` are
  exactly these four rows, named after the documentation section:
  - `iam-ug.permissions-boundaries.resource-based-policies.iam-user-arn.not-limited-by-boundary`
  - `iam-ug.permissions-boundaries.resource-based-policies.iam-role-arn.limited-by-boundary-and-session-policy`
  - `iam-ug.permissions-boundaries.resource-based-policies.role-session-arn.not-limited`
  - `iam-ug.permissions-boundaries.resource-based-policies.federated-user-session.limited-by-boundary-and-session-policy`

**Cross-account** (IAM User Guide › "Cross-account policy evaluation logic"): the
identity side (identity policy, boundary, session policy, the principal's SCPs) and
the resource side (resource policy, the resource's RCPs) must **both** allow.

**KMS** (AWS KMS Developer Guide › "Key policies in AWS KMS" › "Default key policy"):
the key policy must allow, either directly or by naming the account root, which
enables IAM policies to grant access. An IAM policy alone never grants access to a
key whose policy does not delegate. KMS **grants** are not in the MVP input list;
**Flag**: unmodelled grants can only *add* access, so their absence is reported as a
coverage gap ("KMS grants not evaluated") rather than silently ignored.

**Role trust policies** are resource-based policies on the role and follow the same
table for `sts:AssumeRole*`. **Flag**: AWS stores role principals by unique ID; a
trust policy referring to a deleted-then-recreated role shows an `AROA…` ID in live
data. Such principals are unresolved → `UNKNOWN`.

**S3 Block Public Access** (S3 User Guide › "Blocking public access to your Amazon
S3 storage"): with `RestrictPublicBuckets`, a public bucket policy only grants access
to AWS service principals and authorised users in the bucket owner's account. Applied
at account and bucket level; the most restrictive combination applies
(`Inventory.RestrictPublic`: on when either is on; otherwise unknown when either
is unknown; an account whose setting is not in the input leaves the bucket's).
Sources: `s3control GetPublicAccessBlock` (live, snapshot file
`<account>/s3control/get-public-access-block.json`) and Terraform
`aws_s3_account_public_access_block` (`account_id`, else the provider's account;
a `restrict_public_buckets` that is not a literal is unknown, a gap). **Flag**: S3 ACLs are not modelled; reported as a gap
unless Object Ownership is `BucketOwnerEnforced` (ACLs disabled).

**Session policies** are rarely visible in static inputs. When a chain does not show
one, we assume none; this is listed in the finding's assumptions.

### 6.2 Three-valued logic (UNKNOWN)

Each statement evaluates to *applies*, *does not apply*, or *unknown* (an unresolved
condition key, policy variable, or principal). Combination:

- A definite applicable Deny ⇒ `DENY`.
- Otherwise, an *unknown* Deny ⇒ the result is at most `UNKNOWN` (it cannot be
  `ALLOW`); if nothing would allow anyway ⇒ `IMPLICIT_DENY`.
- Otherwise an allow requirement satisfied only by *unknown* statements ⇒ `UNKNOWN`.
- Information order: `DENY`, `IMPLICIT_DENY` < `UNKNOWN` < `ALLOW` for access
  purposes. Property tests (§6.4) are stated against this order.

**Two kinds of UNKNOWN (Phase 6 review).** An `UNKNOWN` decision says why
(`Decision.DenyOnly`):

- **deny-only:** every required allow is definitely satisfied, and only
  *unknown* Deny statements stand between the request and `ALLOW`. Resolved
  in the attacker's favour (no unknown Deny applies), the request is allowed.
- **needs an unknown allow:** some required allow (identity, resource or
  key policy, boundary, SCP, session policy) is satisfied only by *unknown*
  statements.

Severity is computed from the resolution that gives the attacker the most
access (SCORING.md §1): an UNKNOWN is never a reason for a lower score. The
kind of UNKNOWN sets the path's **status** and **confidence** only:

| Status | When | Confidence |
|---|---|---|
| `confirmed` | no UNKNOWN on the path, every precondition known satisfied | the lowest edge confidence (`high`, or `medium` for a lower-confidence escalation) |
| `confirmed_unless_denied` | the only UNKNOWNs on the path are deny-only | `medium` |
| `unconfirmed` | the path needs an unknown allow, or an UNKNOWN precondition, or an UNKNOWN fact (an RBAC role or a key not in the input) | `low` |

A derived edge (`CAN_READ_PLAINTEXT`) takes the kind of its underlying edges.
Every unknown is named in the finding's `undecided`, with what resolves it:
`tools/refresh-managed-policies` for an AWS managed policy missing from the
snapshot, `assume:` in clapa.yaml for a context key, `--plan` for a value
Terraform resolves, the input to add for a key or a role outside it.
`--fail-on` counts every status at its (worst-case) severity. Property tests:
every resolution of a path's unknowns scores at most what is reported, and
adding an unknown policy to a principal never lowers a severity
(`TestUnknownsNeverLowerSeverity`).

### 6.3 Matching and conditions

- **Actions**: case-insensitive, `*` and `?` over the full `service:action`,
  `NotAction`.
- **Resources**: ARN parsed into partition/service/region/account/resource; `*`/`?`
  are matched per segment for the first five; the resource part is matched as a
  whole (it may contain `/` and `:`). `NotResource`. `arn:aws:s3:::b` ≠
  `arn:aws:s3:::b/*`. **Flag**: whether `*` may span `:`-separated segments is
  pinned by tests citing IAM User Guide › "IAM JSON policy elements: Resource".
- **Principals**: `"*"`, `{"AWS":"*"}`, account root / bare account ID, role ARN,
  assumed-role session ARN, `Service`, `Federated`, `CanonicalUser`, `NotPrincipal`.
- **Policy variables** (`${aws:username}`, `${aws:PrincipalTag/x}`, …) — not in the
  spec. **Flag**: substituted when the context provides the value, otherwise the
  match is *unknown*. Never treated as literal text.
- **Conditions** (IAM User Guide › "IAM JSON policy elements: Condition operators"
  and "…: Condition"):
  - Families: String, Numeric, Date, Bool, Binary, IpAddress, Arn, Null.
  - Different operators and different keys in a block: AND. Several values for one
    key: OR — but **NOR for negated operators** (`StringNotEquals`, …).
  - Key **known absent**: positive operators ⇒ false; negated operators ⇒ true;
    `…IfExists` ⇒ true; `Null:true` ⇒ true.
  - Key **unknown to the analyzer** (distinct from "absent") ⇒ *unknown*, with the
    condition attached. Never guessed.
  - `ForAllValues` is true for an empty or absent key (a documented pitfall);
    `ForAnyValue` is false for it.
  - Context assumptions from config (`assume: {"aws:SourceVpce": "vpce-123"}`)
    turn unknown keys into known values; every assumption used is listed in the
    finding.

### 6.4 Correctness

- Corpus ≥ 150 table-driven cases in `internal/eval/testdata/eval/*.yaml`
  (spec says `testdata/eval/`; Go resolves `testdata` per package, so it lives under
  the evaluator). Each case is named after the doc rule it encodes. New cases need no
  code.
- Fuzz targets (`testing.F`): policy-JSON parser (`iampolicy.FuzzParse`), ARN
  parser and wildcard matcher (`arn.FuzzParse`, `arn.FuzzMatch`), and the
  evaluator end to end (`eval.FuzzEvaluate`). Must not panic. CI runs each for
  20 s on every change and 5 minutes nightly (`.github/workflows/fuzz.yml`).
- `rapid` properties: adding an unconditional Deny never increases access;
  narrowing `Resource` never increases access; evaluation is deterministic and
  statement-order independent.
- **Flag — branch coverage.** `go test -cover` measures statements, not branches.
  We gate `internal/eval` and `internal/paths` with `gobco` (branch/condition
  coverage) at ≥ 95%, and the rest with statement coverage (≥ 90% overall).
  *Implemented (Phase 2):* `task cover:branch` gates `eval`, `eval/condition`,
  `eval/match`, `arn`, `iampolicy` and `model`; all at 100% when Phase 2 closed.
  A switch over every member of an enum leaves its last case impossible to be
  false, so such dispatches are written as if-chains; this keeps the
  `exhaustive` linter and branch coverage from contradicting each other.

### 6.5 Decisions made while implementing (Phase 2)

Each item is encoded by corpus cases (file in parentheses).

| Topic | Decision | Why |
|---|---|---|
| Signature | `Evaluate(*Request, *PolicySet) Decision` (pointers instead of the spec's values) | `gocritic hugeParam`; semantics unchanged, inputs are never mutated |
| Duplicate JSON keys | rejected by the parser | `encoding/json` silently keeps the last; AWS's handling is not something to guess (iampolicy tests) |
| RCP syntax | RCP statements require `"Principal": "*"` | AWS Organizations › RCP syntax; first draft wrongly forbade it (13) |
| SCP scope | SCPs are not applied to AWS service principals, web identities or anonymous callers | Organizations › SCPs govern principals in member accounts (13) |
| RCP scope | RCPs are applied to every caller except where policies do not match | **Flag:** whether RCPs exempt service principals is not modelled; applying them can only hide access the RCP really blocks |
| Empty condition value list | `UNKNOWN` | AWS does not document it (06) |
| Multivalued key without `ForAnyValue`/`ForAllValues` | `UNKNOWN` | IAM › multivalued context keys warns against it; behaviour not pinned (09) |
| Non-numeric value in a Numeric* comparison (policy or request side); likewise unparsable Date*, Bool, IpAddress and base64 values | `UNKNOWN`, never ALLOW | AWS does not document the result; independently confirmed by the external review case `clapa.indep.numeric-non-number` (07, 99) |
| `Principal: "*"` grant + boundary/session policy that does not allow | `UNKNOWN` | the boundary table (§6.1) does not cover the wildcard principal (05) |
| `{"AWS": "*"}` vs service / web-identity callers | `UNKNOWN` | equivalence with `"*"` is documented for AWS principals and anonymous only |
| NotPrincipal | caller excluded only if its own ARN **and** account are listed; for a role session the documented list also has the role ARN — session + account without role ARN is `UNKNOWN` | IAM › NotPrincipal › "Specifying NotPrincipal with Deny" (16); the first draft treated partial lists as UNKNOWN, the corpus showed the documentation decides most of them |
| Policy variables | interpreted only in `2012-10-17`; `${key, 'default'}` supported; absent key without default → the element matches nothing; multivalued or unknown key → `UNKNOWN`; unterminated `${` is literal; substituted values are literal (a `*` in a value is not a wildcard) | IAM › Policy variables (14, 17) |
| ArnEquals vs ArnLike | identical: each of the six ARN components is matched with wildcards | IAM › ARN condition operators (08) |
| Root user | identity policies do not apply; full access in its own account unless the resource policy must allow (KMS); cross-account needs a resource grant; SCPs apply | IAM › root user; KMS › key policies (17) |
| Context | keys are **unknown** unless stated; "absent" must be stated (or set as the default) | an unstated key is not evidence of absence |

Property tests (`rapid`, 5000 cases each locally) caught one test-harness bug:
`rapid.Permutation` turns an empty slice into `nil`, which changes "empty
boundary (allows nothing)" into "no boundary". The harness now preserves it.

---

## 7. Access graph and path engine

### 7.1 Graph

`internal/graph`: a typed directed multigraph in compressed-sparse-row form
(`int32` node indices, edges sorted by (from, kind, to, edge-ID)) for deterministic
iteration and low memory. Each edge carries `kind`, the evaluator `Decision` with
justifying statements, preconditions, `confidence ∈ {high, medium, low}` and a
**cut cost** (§9.1, `docs/SCORING.md`). No third-party graph library: we need typed
edges, stable ordering and a max-flow over our own representation.

### 7.2 Edge kinds

`RUNS_AS`, `ASSUMES` (SA → role via IRSA/Pod Identity; role → role via
`sts:AssumeRole`), `NODE_ROLE` (precondition-gated), `CAN_ESCALATE` (PassRole +
compute-create, `CreatePolicyVersion`, `Attach/PutRolePolicy`,
`UpdateAssumeRolePolicy`, `sts:AssumeRole` on `*`, K8s `create pods`/`pods/exec`/
`impersonate`/`bind`/`escalate`), `CAN_READ`, `CAN_DECRYPT`, `PROTECTS`,
`EXPOSED_TO`, plus `MAPS_TO` (IAM principal → K8s user/group via `aws-auth` or
access entries).

**Escalation (Phase 6 review).** `CAN_ESCALATE` means obtaining **another**
identity: creating a pod as another service account, `pods/exec` into
another's pod, `impersonate`, `serviceaccounts/token` for another service
account (RBAC); `iam:PassRole` into compute, rewriting a trust or a policy
(IAM). A workload using its own credentials, cloud or Kubernetes, is
`RUNS_AS`; a path with a `CAN_ESCALATE` edge is `CLAPA-PATH-002`, one without
is `CLAPA-PATH-001`. Minting a token for the account itself
(`ASSUMES[minted-self]`, scenario 4b) is not another identity, so scenario 4b
is `CLAPA-PATH-001`.

**Edge semantics (Phase 4, written before the access builder):**

| Edge | From → to | Exists when | Cost |
|---|---|---|---|
| `RUNS_AS` | workload → its service account | always (the cloud identity a pod's credentials carry) | 100 |
| `RUNS_AS[k8s-token]` | workload → its service account | the service account token is mounted (`automountServiceAccountToken`, §4.7 default `true`): the pod acts in the Kubernetes API as its **own** service account. That is direct access, like `RUNS_AS`, not escalation (Phase 6 review; it was `CAN_ESCALATE[k8s-token]`). The IRSA web-identity token is projected separately and does not need it. After it, a path may use the account's RBAC (§7.4 modes) | 5 (workload, revoke: `automountServiceAccountToken: false` takes away the RBAC rights the path uses, granted on purpose; Phase 6 review, it was narrow, 3). Without an RBAC binding used on the path, the token is on no path: turning it off is hardening (`CLAPA-POST-004`), never a cut |
| `CAN_ESCALATE[rbac]` | service account → service account | RBAC lets the first `create pods` or `pods/exec`, `create serviceaccounts/token`, or `impersonate serviceaccounts` in a namespace: it can act as any of that namespace's service accounts | 5 |
| `ASSUMES[irsa]` | service account → role | the service account carries `eks.amazonaws.com/role-arn`, so its pods get a token for its `eks.amazonaws.com/audience`; the role's trust allows `sts:AssumeRoleWithWebIdentity` for its `sub`/`aud`, **and** the OIDC provider accepts the audience: STS requires `aud` to be one of the provider's client IDs (IAM User Guide › "Create an OpenID Connect (OIDC) identity provider"). A provider in the input decides by its `client_id_list`; without one, `sts.amazonaws.com` is accepted as a documented default (§4.7) and any other audience is UNKNOWN. The annotation is not a security boundary: the token works with every role that accepts it | 5 |
| `ASSUMES[projected]` | workload → role | the pod spec projects a `serviceAccountToken` volume with an audience: the same check as IRSA, with no annotation needed | 5 |
| `ASSUMES[minted]`, `ASSUMES[minted-self]` | service account → role | a node that controls the service account (RBAC above) obtains a token for it with any accepted audience (a pod with a projected token, or TokenRequest) and assumes every role whose trust accepts its `sub`. `minted` is usable only after `CAN_ESCALATE[rbac]` into the account; `minted-self` also straight from the account's own Kubernetes token, when its own RBAC holds the right (scenario 4b). Never from `RUNS_AS` alone | 5 |
| `ASSUMES[pod-identity]` | service account → role | an association links them and `access.PodIdentityAssume` allows (§4.6) | 5 |
| `ASSUMES[sts]` | role → role | the source's identity policies allow `sts:AssumeRole` on the target **and** the target's trust allows the source session | 5 |
| `CAN_ESCALATE[iam:passrole:<service>]` | role → role | `iam:PassRole` on the target (with `iam:PassedToService`), the target trusts the service, and the create actions are allowed: Lambda (`CreateFunction`; runs with `InvokeFunction`, `CreateEventSourceMapping` or `CreateFunctionUrlConfig`), EC2 (`RunInstances`), ECS tasks (`RegisterTaskDefinition`; `RunTask`, `StartTask` or `CreateService`), CloudFormation (`CreateStack`), Glue (`CreateJob`; `StartJobRun`), CodeBuild (`CreateProject`; `StartBuild`), SageMaker (`CreateNotebookInstance`). Where creating runs the code, it is the execution; without an execution primitive, `confidence: medium` | 2 |
| `CAN_ESCALATE[iam:update-trust]` | role → role, **same account only** | `iam:UpdateAssumeRolePolicy` on the target: the source names itself in the trust and assumes it. IAM's only resource-based policy is the role trust policy, which governs `sts:AssumeRole`, not IAM writes (IAM User Guide › "AWS services that work with IAM": IAM, resource-based policies "Partial"; "Resource-based policies" › role trust policies), so a role in another account can be rewritten only after an `ASSUMES` into that account; that path is the chain plus a same-account edge. Corrected at the Phase 6 review (it allowed another account with `sts:AssumeRole`) | 2 |
| `CAN_ESCALATE[iam:modify-policy]` | role → "role (any permission)" | `iam:AttachRolePolicy` or `iam:PutRolePolicy` on the target, or `iam:CreatePolicyVersion` on a customer managed policy attached to it, when the source is or can become the target. The synthetic principal's identity policy allows everything; the target's permissions boundary, resource policies and key policies still apply | 2 |
| `MAPS_TO` | IAM principal → Kubernetes user / group | `aws-auth` `mapRoles`/`mapUsers` (a `rolearn` carries no path, so a role matches by account and name) or an EKS access entry (`aws_eks_access_entry`: user name, groups). The subject's RBAC then gives `CAN_ESCALATE[rbac]`; `system:masters` is cluster-admin without a binding. An access policy association gives the principal the policy's rules directly (ClusterAdmin: all; Admin: create pods, impersonate service accounts; Edit: create pods; View, AdminView: read only — EKS User Guide › "Access policy permissions"); another policy is UNKNOWN | 8 |
| `NODE_ROLE` | workload → node role of its cluster's node groups | IMDS is reachable: `hostNetwork: true` (any token setting, unless `http_endpoint` is disabled), or `http_tokens` optional, or hop limit ≥ 2; precondition, factor 900 when known, 500 when unknown | 3 |
| `CAN_READ`, `CAN_DECRYPT[for J]`, `CAN_READ_PLAINTEXT` | principal → jewel / key | §7.3 | §9.1 |
| `CAN_READ_PLAINTEXT[k8s]` | Kubernetes subject (service account, user, group, or an IAM principal by EKS access policy) → Kubernetes Secret | RBAC lets the subject `get`, `list` or `watch` the Secret: core API group, `secrets` or `*`, its namespace (or cluster-wide), and no `resourceNames` or its name. `list` and `watch` return the data too. The API returns the value decoded, so there is no decrypt step. A role that is not in the input makes the edge UNKNOWN. **The path search allows it only after `RUNS_AS[k8s-token]`, a `MAPS_TO` or an RBAC escalation**, never with the cloud identity alone (`paths.allowed`). A read with the pod's own token is direct access: `CLAPA-PATH-001` (scenario 21); its severity comes from the Secret's classification (§5), as for any target | 5 (rbac, revoke) |
| `CAN_READ_PLAINTEXT[mount]` | workload → Kubernetes Secret of its namespace (Phase 7) | the pod spec names the Secret: a `secret` volume, a `secret` source of a `projected` volume, or `env[].valueFrom.secretKeyRef` / `envFrom[].secretRef` of any container, init or ephemeral container. The kubelet gives it to the pod with no RBAC check on its service account (Kubernetes › Secrets, "Using Secrets as files from a Pod", "Using Secrets as environment variables"). `imagePullSecrets` go to the kubelet, not the containers, and are not edges | 5 (workload, revoke: stop naming the Secret; the generator removes the volume, its mounts and the env entries) |
| `CAN_READ_PLAINTEXT[pod-create]` | Kubernetes subject → each Kubernetes Secret of a namespace where it may create pods (Phase 7) | RBAC `create` on `pods` (core group, every name; a cluster-wide grant counts in every namespace): a pod it creates may name any Secret of the namespace (Kubernetes › RBAC Good Practices, "Workload creation"). An RBAC right, so a path reaches it after `RUNS_AS[k8s-token]` (§7.4 modes); `pods/exec` is not counted (it enters an existing pod, whose Secrets are its `[mount]` edges). A grant whose role is not in the input already gives an unknown `[k8s]` read and adds no second edge | 5 (rbac, revoke) |

### 7.3 Encrypted data access

Reading encrypted data needs `CAN_READ` on the object **and** `CAN_DECRYPT` on its
key, each evaluated with the right context (`kms:EncryptionContext:aws:s3:arn`,
`kms:ViaService`, …).

The conjunction applies only when the data is protected by a **KMS key** (S3
SSE-KMS / DSSE-KMS, Secrets Manager, SSM SecureString). For S3 objects that are
unencrypted or use SSE-S3 (`AES256`, S3-managed keys), there is no KMS
authorization step, so `CAN_READ` alone yields plaintext (S3 User Guide › "Using
server-side encryption with Amazon S3 managed keys"). When the encryption
configuration is unknown (not in the input), the edge to plaintext is `UNKNOWN`
with a recorded gap, never assumed in either direction.

**Secret stores (Phase 6).** Each one reads with its own API and decrypts with
its own encryption context (`model.EncryptionContextKey`), and the remediation
conditions use the same key.

- **Secrets Manager.** `CAN_READ` is `secretsmanager:GetSecretValue`, evaluated
  on the identity policies and the secret's resource policy.
  `CAN_DECRYPT[for S]` is `kms:Decrypt` with:
  - the encryption context `SecretARN` = the secret's ARN, and
    `SecretVersionId` unknown (Secrets Manager User Guide › "Secret encryption
    and decryption");
  - `kms:EncryptionContextKeys`;
  - `kms:ViaService` = `secretsmanager.<region>.amazonaws.com`;
  - `kms:CallerAccount`.
- **SSM Parameter Store.** `CAN_READ` is any of:
  - `ssm:GetParameter`, `GetParameters` or `GetParameterHistory` on the
    parameter's ARN;
  - `GetParametersByPath` on any ancestor path, since it is authorized on the
    path (Systems Manager User Guide › "Restricting access to Parameter Store
    parameters using IAM policies").

  A SecureString also needs `CAN_DECRYPT` with the context `PARAMETER_ARN` and
  `kms:ViaService` = `ssm.<region>.amazonaws.com` (Systems Manager User Guide ›
  "AWS KMS encryption for … SecureString parameters"). `String` and
  `StringList` parameters are plaintext.
- **The AWS managed keys.** For `aws/secretsmanager` and `aws/ssm`, principals
  of the resource's account may decrypt, and no other account may (documented
  defaults, §4.7).
- **Unknown keys (every encrypted target, S3 included; Phase 6 review).** A
  key that is not in the input, or an alias that is not resolved, is a key
  whose key policy is unknown: `CAN_DECRYPT` is UNKNOWN (an unknown allow:
  the key policy must allow), never "no edge", and the scan records a
  coverage gap naming the key and the resource it protects. The path is
  `unconfirmed` at its worst-case severity. The anonymous caller still cannot
  use a KMS key.
- **Sources.** Snapshots and live collection; also Terraform
  (`aws_secretsmanager_secret` and its policy, `aws_ssm_parameter`). A secret's
  ARN suffix is unresolved until apply, so a policy naming one exact secret ARN
  is UNKNOWN for it.
- **Not modelled**, and listed in every report:
  - admission policies (Pod Security admission, policy engines) that could
    reject a pod naming a Secret: `CAN_READ_PLAINTEXT[mount]` and
    `[pod-create]` (§7.2, Phase 7) assume the pod is admitted;
  - AWS RAM shares of advanced parameters.

**Decision.** `CAN_DECRYPT` edges are **qualified by the protected resource**: the
edge `role —CAN_DECRYPT[for bucket Z]→ key K` is evaluated with Z's encryption
context. A grant scoped to bucket Y's context yields no edge for Z. The `access`
builder derives `CAN_READ_PLAINTEXT` (principal → jewel) only when both edges exist,
and records both as evidence. A cut on the derived edge maps to the cheaper of its
two underlying edges, which keeps legitimate access to Y through the same key cuttable
independently of the attack path to Z.

### 7.4 Path search and chokepoints

**Flag (accepted in plan review) — "find every path" is exponential.** Decision:

1. **Reachability** from all entry points (multi-source BFS) decides *whether* a
   jewel is reachable. This is exact and linear.
2. **Path enumeration** for explanation: depth-first, cycle-safe, deterministic,
   max depth (default 10), and a per-(entry, jewel) cap (default 100). When a cap
   is hit the report says so; it is never silent.
3. **Chokepoints** are computed by **weighted minimum cut** (Dinic max-flow,
   integer capacities = cut costs, `∞` for uncuttable edges) between a super-source
   over the entries and the jewel. We choose the canonical cut closest to the source
   (residual reachability) for determinism.
4. **Grouping across jewels** is greedy (exact minimum multicut is NP-hard): repeatedly
   take the cut that breaks the most uncovered paths per unit cost. Documented as an
   approximation.
5. Chokepoints are ranked by the number of paths they break, then by cost.

**Implementation (Phase 4).** The search runs over (node, mode) states: after
`RUNS_AS` a pod holds its cloud identity but not its Kubernetes token, after
`RUNS_AS[k8s-token]` only the token, after creating a pod both (§7.2). Per
entry: one breadth-first reachability, one depth-first walk that collects the
paths to all of its jewels (100 per jewel, depth 10; a jewel is marked
truncated when a cap or the depth bound stops a walk that could still reach
it), and one flow network shared by its jewels — each graph edge is a single
capacity arc shared by its mode copies, so a cut is exact; per jewel only its
states' arcs to the sink are added. The representative path of a finding is
its highest-scoring path (ties: fewer edges). A rapid property compares Dinic
with brute force on random graphs of up to 8 nodes.

**Capacities (third and fourth Phase 4 reviews).** An edge's capacity is the
cheapest change that breaks it, priced per side (identity, resource, trust,
workload, rbac, mapping, node; SCORING.md §4.1), and per kind: narrowing a
broad grant costs the side's price, revoking an explicit grant 2 more. The
kind comes from the side's granting statements (`eval.Granting`: the Allow
statements of those policies that apply to the request). The access builder decides each
evaluator-decided edge again without each side's policies and keeps only the
sides whose removal really stops the grant. It drops the sides a principal can
undo (SCORING.md §4.2): a "role with any permission" has no identity side; a
principal that can rewrite the target's bucket policy, key policy (or create a
KMS grant) or trust policy has no resource/trust side there, and no identity
side either when it is in the resource's account. An edge with no side left is
uncuttable, so the cut moves before that principal. Shared fixes (one policy
change breaking several cut edges) are only flagged
(`shared_fix_possible`) until Phase 5.

Performance target: 50k nodes / 500k edges in < 60 s and < 2 GB.
**Measured (2026-11-20, i7-10850H, Go 1.27):** 50,000 nodes, 542,000 edges,
30,000 entries, 1,136,630 (entry, jewel) pairs: 22.5 s, at most 755 MiB
obtained from the OS (`TestPerformanceTarget`, `CLAPA_PERF=1`; run by
`bench.yml` on every pull request). `internal/paths`
ships `-benchmem` benchmarks with a synthetic graph generator (Phase 4).
**Flag — CI benchmark noise.** Shared runners are noisy; the bench job runs base and
head on the **same runner in the same job**, `-count=10`, compares with `benchstat`,
and fails on a statistically significant regression > 20%.

---

## 8. Rules and findings

```go
type Rule interface {
    Meta() Meta                         // ID, semver, title, rationale, references, fixtures
    Evaluate(in Input) []Finding        // pure
}
```

Rules are registered in an explicit `*rules.Registry` built by `catalog.New()` —
no package-level mutable registry, no `init()` side effects. The catalog version is
a semver bumped when any rule's ID set or version changes (checked by a test).
Each rule has: stable ID, semver, title, rationale, severity logic, references
(MITRE ATT&CK technique, CIS control, AWS/K8s doc), at least one passing and one
failing fixture. `clapa rules list|show`.

**Fingerprint** = `sha256(rule ID, rule major version, canonical IDs of entry and
jewel)` for a path finding (the posture form is in §8.1). It names the
**problem, not its fix** (decided in the third Phase 4 review): which rule, from
which entry, to which crown jewel. The path, the cut, its cost and every weight
are left out, so re-pricing a fix (SCORING.md §4), changing `remediation.cut_costs`
or a new chokepoint never resets a suppression or a baseline; a property test
draws random cut-cost tables over every fixture and requires every fingerprint
to stay the same. File lines are left out too, so moving code does not reset
suppressions. One finding exists per (rule, entry, jewel), so the fingerprint
stays unique (scenario 14 checks distinct fingerprints).

**One finding per rule (Phase 6 review).** Each path rule reports its own
finding for an (entry, jewel) pair, from the paths of its own class:
`CLAPA-PATH-001` from the paths without `CAN_ESCALATE`, `CLAPA-PATH-002` from
those with one, `CLAPA-PATH-003` from the anonymous entry. A pair reached both
directly and through an escalation is two findings, so adding an input (an
unknown policy, a new path) never makes a finding disappear or changes its
fingerprint. Within one finding:

- **severity** is the highest among the rule's paths (the worst case);
- **status** is the strongest among them: `confirmed` if one path is
  confirmed, else `confirmed_unless_denied` if one is, else `unconfirmed`;
- **the path shown** is the best path of the strongest status; when a less
  certain path scores higher, it is `worst_case_path` (its path, status,
  score, severity and what it leaves undecided), and the finding's score and
  severity are that path's;
- **the cut** breaks every path of the rule for the pair;
- **`also_fixes`** lists the fingerprints of the path findings of *other*
  rules whose every path the cut also breaks (scenario 6: one change fixes
  both the direct read and the escalation). Posture findings are not
  listed: a cut breaks paths, and whether a fix also removes a posture
  finding is what remediation verification tells (§9.3).

**Dominated escalations (Phase 6 review).** A path through `CAN_ESCALATE`
from a principal X to a target J is **dominated**, and ignored, when X itself
reaches J without an escalation at an equal or stronger status (statuses
ordered `confirmed` > `confirmed_unless_denied` > `unconfirmed`; severity is
not compared: it is the same target). The escalation is kept when X has no
direct access to J, or only a weaker one: then the escalation adds access, or
certainty. "X reaches J without an escalation" means a path from X to J with
no `CAN_ESCALATE` edge, under the same search rules (§7.4). Without this rule,
before the managed-policy snapshot is refreshed, every role with an unknown
policy would add a `CLAPA-PATH-002` for every target it already reads.

- Scenario 6: `analytics-admin` reads the warehouse with AdministratorAccess
  (confirmed); rewriting its own policies adds nothing: no `CLAPA-PATH-002`.
- Scenario 19 with ReadOnlyAccess: `payments-api` reads the secret directly
  (`confirmed_unless_denied`); the escalation through the unknown policy is
  `unconfirmed`, weaker: dominated, no `CLAPA-PATH-002`.
- Scenario 22: `role/ops` reads nothing itself; its escalation (it rewrites its
  own policy) is the only way it reaches the data: kept, a `CLAPA-PATH-002`
  beside `role/app`'s own `CLAPA-PATH-001`. In its dominance variant
  `role/app` reads the data itself, confirmed, and could also rewrite its own
  policy: that escalation is dominated.

A dominated path is hidden from the report, not removed: it belongs to the
finding that dominates it for the **cut** and for **verification**. The cut
of the dominating finding breaks all its paths, the dominated ones included;
otherwise cutting the direct path alone would make the escalation no longer
dominated, a new `CLAPA-PATH-002` would appear for the same pair, and the
fix would not fix the problem. Verification rejects a fix after which any
finding appears for the same (entry, jewel): in scenario 22's dominance
variant, cutting `role/app`'s decrypt alone is rejected
(`TestDominatedPathsStayInTheCut`).

How the engine does it (`internal/rules/pathrules`, `internal/paths`): the
paths of a pair are split by rule; an escalation is dominated when the
source X of its first `CAN_ESCALATE` reaches the jewel without one at a
status at least as strong as the rest of the path from X. The cut of each
finding is a minimum cut over its own selection of paths, on a network
expanded by (node, mode, escalated): the direct finding's paths may take an
escalation only from a dominated source; the escalation finding's must take
one from a source that is not. X's escalations are merged into the direct
cut when all of them are dominated; when only some are, all of X's
escalations stay with the escalation finding's cut (the dominated ones are
not reported, but they are cut there). When the direct paths of a pair were
not enumerated (caps), the escalations are reported rather than hidden.
Properties (`internal/app/phase6_properties_test.go`): an unknown policy
never hides a confirmed finding or changes its fingerprint, an unknown Allow
never lowers its status; no escalation finding has a dominated path;
applying a finding's cut in memory leaves no new finding for its pair.

**Suppressions** (`.clapa-ignore.yaml`, or `--ignore FILE`; Phase 6):

- Keyed by fingerprint, each with a mandatory `reason`, `owner` and `expires`
  (date, inclusive).
- A missing field is a configuration error (exit 2), and so is an explicit
  `--ignore` file that does not exist. The default file may be absent.
- A suppressed finding moves to the report's `suppressed` list and does not
  count for the exit code.
- An expired suppression does not apply: its finding fires again, it is listed
  in `expired_suppressions`, and the console warns.

**`--baseline previous.json`** takes a previous JSON report:

- only new findings are reported, and they decide the exit code;
- `baseline.resolved` lists the previous report's findings that are gone;
- a suppressed finding is still there, so it is not resolved.

Tested end to end through the CLI.

Scoring: `docs/SCORING.md`.

### 8.1 Rule catalog (Phase 4; decided in review)

IDs are stable; a rule's semantics change only with its semver. MITRE ATT&CK
technique IDs below are the intended mapping; CIS control numbers are added
per rule only after they are checked against the benchmark text.

| ID | Kind | Fires when | Base / scoring | ATT&CK |
|---|---|---|---|---|
| `CLAPA-PATH-001` | path | an entry workload reaches `CAN_READ_PLAINTEXT` on a crown jewel through `RUNS_AS`, `ASSUMES`, `NODE_ROLE`, `MAPS_TO` edges (no escalation) | SCORING.md §1 | T1078.004, T1530 |
| `CLAPA-PATH-002` | path | as PATH-001, with at least one `CAN_ESCALATE` edge on the path (IAM or Kubernetes escalation) | SCORING.md §1 | T1098, T1548, T1610, T1530 |
| `CLAPA-PATH-003` | path | the anonymous principal reaches `CAN_READ_PLAINTEXT` on a crown jewel (a resource policy that grants a public principal, with Block Public Access not known to be on) | SCORING.md §1, exposure 1000 | T1530 |
| `CLAPA-POST-001` | posture | (rule 1.0.1) an IRSA trust policy allows `sts:AssumeRoleWithWebIdentity` for a service account that is not in the input, probed in a namespace of its own and in every namespace of the cluster (a wildcard scoped to one namespace) — decided by the evaluator with a probe subject `system:serviceaccount:clapa-probe:clapa-probe` (catches wildcard `:sub` and `:aud`-only trusts) | high | T1078.004 |
| `CLAPA-POST-002` | posture | a node group allows IMDSv1 (`http_tokens` known `optional`) | high | T1552.005 |
| `CLAPA-POST-003` | posture | a container runs `privileged: true` | high | T1611 |
| `CLAPA-POST-004` | posture | a workload automounts its service account token and that service account has RBAC permissions | medium | T1528 |
| `CLAPA-POST-005` | posture | a crown-jewel bucket's Block Public Access `restrict_public_buckets` is known off (stated in the input; no default exists, §4.7) | high | T1530 |
| `CLAPA-POST-006` | posture | a symmetric customer managed KMS key has rotation off (Terraform `enable_key_rotation` false, or unset: documented default `false`, §4.7) | medium | — |
| `CLAPA-POST-008` | posture | a sensitive action (`kms:Decrypt`, `sts:AssumeRole`, `iam:PassRole`, `s3:GetObject`, `secretsmanager:GetSecretValue`, `ssm:GetParameter`, or a wildcard covering one) is allowed on every resource (`"*"`, `NotResource`, or an ARN whose resource part is `*`, `*/*` or `<type>/*` for a non-S3 type) by an identity policy whose permissions boundary keeps it, or to every principal (`Principal "*"`) by a bucket, key or trust policy; in both cases with no condition or only organization/account conditions. One finding per principal or resource (added in the Phase 5 review: a mitigation leaves the grant, and this keeps it visible) | graded by reachability (rule 1.1.0, catalog 1.2.0): **high** when an entry point reaches the principal holding the grant — a workload directly, IRSA, Pod Identity, `CAN_ESCALATE`, an `ASSUMES` chain; for a grant to every principal, any reached principal, or the anonymous caller when it has no condition — so a mitigated scan of a reachable grant is not clean at `--fail-on high`; **medium** when no path reaches it (real accounts hold intended admin roles: break-glass, platform). The evidence says `reachable_from: [<entries>]` or `reachable_from: none`. 06 fixed: `analytics-admin` medium, exit 0 | T1078.004 |
| `CLAPA-POST-007` | posture | a namespace has workloads in the input and no NetworkPolicy that selects every pod with an `Ingress` policy type and no ingress rules (default deny) | medium, `confidence: medium` (policies may live outside the input) | — |

**Decisions (Phase 4 review):**

1. **Posture rules and unstated settings.** A setting the input does not state
   takes its documented deterministic default (§4.7) and the finding's evidence
   says `value_source: default` with the reference; e.g. an unstated
   `automountServiceAccountToken` is `true`, so CLAPA-POST-004 fires, and an
   unstated Terraform `enable_key_rotation` is `false`, so CLAPA-POST-006 fires.
   Only a setting with no deterministic default (IMDS, Block Public Access, a
   snapshot's rotation status) is a coverage gap — never a finding and never
   "compliant".
2. **Data is the asset; a KMS key is a means of reaching it.** Reading
   plaintext needs both the object and its key (§7.3), so the harm is defined at
   the data: a path ends at `CAN_READ_PLAINTEXT` on the data, and a key is not a
   separate jewel and is not counted in blast radius. (That this keeps the
   SCORING.md worked example at 729 is a consequence, not the reason.) A key
   classified as a crown jewel that protects **no resource in the input** is not
   dropped: it is reported as a coverage note (`protected-data-outside-input`):
   the data it protects is outside the input, so paths to that data are not
   analysed. *Future work:* an impact kind for **administrative control of a
   key** (`kms:PutKeyPolicy`, `kms:ScheduleKeyDeletion`, `kms:DisableKey`), which
   threatens availability and future access rather than reading data.
3. **Tie-break under a derived read.** When `CAN_READ` and `CAN_DECRYPT` under a
   `CAN_READ_PLAINTEXT` cost the same, the chokepoint is `CAN_DECRYPT[for jewel]`
   (qualified by the protected resource, so an encryption-context condition
   removes exactly this path). *Revised in the fourth Phase 4 review:* since a
   revoke costs 2 more than a narrow fix (SCORING.md §4.1), the cheaper edge
   usually wins outright and the rule only decides exact ties (no fixture has
   one); the other underlying edge is reported as `alternative_fix` whatever
   its cost, with its own fix in `alternative_fix_detail`.
4. **Fixture 13 states its encryption.** Both variants now declare SSE-S3
   explicitly; the S3 default itself is tested separately (a bucket without any
   encryption configuration is SSE-S3 with `value_source: default`).

**Posture finding identities.** A posture finding names one resource: its ARN
when it has one, its Kubernetes identity (`k8s:{cluster}/{namespace}/{kind}/{name}`;
a namespace is `k8s:{cluster}//Namespace/{name}`), or `eks-nodegroup:{cluster}/{name}`
for a node group. Its fingerprint is `sha256(rule ID, rule major version,
canonical ID of the resource)`. The anonymous principal is `anonymous`.

**`--fail-on` default: `high`.** Exit 1 needs a finding at or above it
(unconfirmed findings count, SCORING.md §1.3).

### 8.2 `expected.json` (format `clapa-expected/v1`)

Written by hand from §13.2 and §13.1 (and, for posture rules, from reading the
fixture files) **before** the rules run; never generated from tool output. A
mismatch is investigated and shown in review; the file is never edited to match
the tool.

```json
{
  "format": "clapa-expected/v1",
  "derived_from": "DESIGN.md §13.2 row 1; §13.1",
  "exit_code": 1,
  "findings": [{
    "rule": "CLAPA-PATH-001",
    "entry": "k8s:prod/payments/Deployment/api",
    "jewel": "arn:aws:s3:::acme-customer-pii",
    "path": ["RUNS_AS k8s:prod/payments/ServiceAccount/api",
             "ASSUMES arn:aws:iam::111122223333:role/payments-api",
             "CAN_READ_PLAINTEXT arn:aws:s3:::acme-customer-pii"],
    "confirmed": true, "confidence": "high", "score": 729, "severity": "critical",
    "chokepoints": ["CAN_DECRYPT[for arn:aws:s3:::acme-customer-pii] arn:aws:iam::111122223333:role/payments-api -> arn:aws:kms:us-east-1:111122223333:key/tf-aws_kms_key.pii"],
    "alternative_fix": ["CAN_READ arn:aws:iam::111122223333:role/payments-api -> arn:aws:s3:::acme-customer-pii"],
    "defaults_used": []
  }],
  "absent": [{"rule": "CLAPA-PATH-001", "jewel": "arn:aws:s3:::acme-payment-receipts"}],
  "intended_access": [{"principal": "...", "action": "s3:GetObject", "resource": "...", "status": "verified"}]
}
```

The files are written by `tests/fixtures/expected_source.py`, which holds the
hand-derived data and the score arithmetic in comments; it only serialises.
The golden test compares rule, entry, jewel, path, confirmation, confidence,
score, severity, chokepoints, `alternative_fix`, the chosen fix's side, kind and
cost (`fix` and `alternative_fix_detail`, where stated) and `defaults_used`, and computes each fingerprint from
these fields with the §8 formula independently of the engine, then compares it with the engine's. Findings the file does not list fail
the test (no extra findings). `entry: null` means "any entry" (the scenario does
not name one); `absent` lists findings that must not appear; `exit_code` and
`collected` are stated only where §13.2 states them (scenarios 13 static and
15), since every other exit code depends on coverage gaps the description does
not enumerate; `parse_errors` lists files that must be reported with a line.

---

## 9. Remediation

### 9.1 Candidates and cut costs

For each chokepoint, deterministic candidate generators per edge kind: scope
`Resource` to exact ARNs; add `kms:EncryptionContext`/`kms:ViaService`; tighten
trust `:sub`/`:aud`; replace a public principal; remove an escalation permission;
disable token automount; require IMDSv2 with hop limit 1.

Every edge kind has a **cut cost** reflecting how disruptive its fix is (table in
`docs/SCORING.md` §4): narrowing a resource or adding a condition is cheap, changing
a trust policy is medium, removing a workload's identity (`RUNS_AS`) is very
expensive, and `PROTECTS` (a structural fact) is uncuttable. This keeps the min-cut
from "fixing" a path by breaking the application's own identity.

**Uncuttable edges.**

```yaml
# clapa.yaml
remediation:
  uncuttable_edges:
    - kind: ASSUMES
      from: "k8s:prod-cluster/payments/ServiceAccount/api"
      to:   "arn:aws:iam::111122223333:role/payments-api"
      reason: "payments API identity; owned by team-payments"
intended_access:
  - principal: "k8s:prod-cluster/payments/Deployment/api"
    action: "s3:GetObject"
    resource: "arn:aws:s3:::payments-receipts/*"
```

- Edges listed in `uncuttable_edges` get capacity `∞` (selectors match canonical
  identities; globs allowed; `reason` mandatory).
- **Every edge on any path that realises a declared `intended_access` is treated as
  uncuttable automatically.** Trade-off: conservative — it can leave no finite cut,
  in which case the report says "no fix within constraints" and names the blocking
  constraints, rather than proposing a fix that breaks intended access.
- Every proposed fix lists, per cut edge: kind, cost, the cost source (default table
  or config override) and the total cost.

**Encryption-context fixes (decided in the Phase 4 review, scenarios 2a–2c).**
A fix that scopes `kms:Decrypt` to one bucket must use the context S3 sends:
with an S3 Bucket Key, `StringEquals kms:EncryptionContext:aws:s3:arn =
<bucket ARN>`; without one, `StringLike … = <bucket ARN>/*` (the object ARN);
with the Bucket Key setting unknown, both forms (`ForAnyValue` over the two
values, or two statements), so the fix works either way. The generator reads
the bucket's Bucket Key setting to choose.

### 9.2 Generation (Phase 5)

For each cut edge the chosen side (SCORING.md §4) gives one change, a list of
**edits to the canonical model** (`internal/remediate`), never text:

| Edge, side | Narrow | Revoke |
|---|---|---|
| `CAN_READ`, identity | add `Deny s3:GetObject` on `<bucket>/*` to the principal's own (inline) policy | remove the explicit `Resource` values; the statement goes when none remain |
| `CAN_READ`, bucket policy | add a `Deny` for the principal; for the anonymous principal, `restrict_public_buckets = true` | remove the principal from the explicit statements |
| `CAN_DECRYPT[for J]`, identity / key policy | add `Deny kms:Decrypt` with the encryption context of J: `StringEquals <J>` with a Bucket Key, `StringLike <J>/*` without, both when unknown (§9.1) | remove the statement bound to J |
| `ASSUMES` (role chain), identity / trust | add `Deny sts:AssumeRole` on the role / for the principal | remove the role / principal values |
| `NODE_ROLE` | IMDSv2 required, hop limit 1 (launch template `metadata_options`) | endpoint off; or remove `hostNetwork` |
| `EXPOSED_TO` | — | the Service becomes `ClusterIP` |

A narrow fix adds an explicit `Deny` scoped to exactly the cut edge (the
action, the target, the principal): the legitimate scope of a broad grant is
not in the input, so the grant is left as written and only this edge is
removed. A revoke deletes the explicit grant, and denies what broad grants
remain. Other edge kinds (escalations, RBAC, mappings, IRSA trusts) are a
**TODO** with what to change by hand.

**Two strategies (decided in the Phase 5 review).** A Deny that blocks one
path leaves the broad grant: every new key, role or bucket is reachable, and a
scan after it must not look clean. So a cut that narrows a broad grant has two
fixes:

- **`root-cause`** narrows the Allow itself (`OpSetValues`): its `Resource`
  (identity side) or `Principal` (resource side) becomes exactly what the
  declared `intended_access` uses through that statement — the targets (or
  principals) of every edge on an intended path that the statement grants.
  It is generated and verified on both levels only when an intended access
  uses the statement. Without one it is a **suggestion**: it lists what the
  wildcard matches in the input, says it is not verified, and `--write` never
  applies it.
- **`mitigation`** is the Deny above, labelled *"mitigation: blocks this path
  only; the broad grant remains"*. It is verified and can be applied at once;
  the grant stays a finding (`CLAPA-POST-008`, high), so the scan after it is
  not clean.

Order in the output: a verified root-cause fix first (then the mitigation);
otherwise the mitigation first, the root cause after it as the unverified
suggestion, and the sentence *"declare intended_access to get a verified
root-cause fix"*. `--write` applies the first fix, and only when it is
verified. A cut that only removes explicit grants or changes settings (revoke,
IMDS, exposure) has one fix, a root cause. Scenario 1b
(`01b_classic_intended`) is scenario 1 with the API's legitimate use declared
(it reads the receipts bucket, its own key): the root cause narrows
`kms:Decrypt` from `"*"` to the receipts key, verified, and the scan after it
is clean.

### 9.3 Verification — two levels, both required

1. **In memory** (`internal/verify`): the edits are applied to a copy of the
   model (`remediate.Apply`) and the evaluator, access builder, path search
   and rules run again. Required: the targeted finding is gone; every
   declared intended access is as before (a verified one stays verified); no
   finding appears and none rises in severity.
2. **On files**: the patch is written into a copy of the inputs in a
   temporary directory outside the scan root, and the scan runs from scratch
   (parse, normalize, evaluate). Its result must equal the in-memory result
   exactly (findings, severities, intended access, exit code). Level 1 shows
   the model change is right, level 2 that the patch is that change; any
   difference rejects the fix.

**Intended access is a hard constraint**: its edges are uncuttable (§9.1), and
the verifier rejects a fix after which a declared entry is worse.

**Definition of done (spec):** for every vulnerable scenario, the patch applied
to a copy and rescanned no longer reports the finding
(`TestEveryVulnerableScenarioIsFixed`: 16 findings). Two are not patched, by
design: scenario 10 is UNKNOWN until the organization ID is known (the
remediation says to set `assume: {"aws:PrincipalOrgID": [...]}`; with it set
the key policy fix is verified, `TestScenario10Decided`; since the Phase 6
review its cut is a `resolve` step, below), and scenario 13's
grant comes from the module input `bucket` (a TODO naming
`terraform/main.tf:4`: the input does not say what the readers need).

**Escalations and detaches (Phase 6 review).** An IAM escalation chosen in
a cut is changed on its identity side like a grant: a revoke removes the
explicit `iam:PutRolePolicy` / `AttachRolePolicy` / `UpdateAssumeRolePolicy`
/ `PassRole` grant of the target, a narrow fix denies those actions on it.
A detach removes the AWS managed policy from the role's
`managed_policy_arns`, or deletes the `aws_iam_role_policy_attachment`,
never editing the AWS document; what replaces it is an unverified TODO in
the change's reason.

**Resolve steps (Phase 6 review; SCORING.md §4.1).** A side that grants
only through an UNKNOWN Allow is fixed by deciding it, not by deleting
anything: `fix_kind: resolve`, cost 0, no patch, the resolving command
named. A cut with one is `remediation_status: partial_pending_resolution`:
`clapa remediate --write` applies only the known steps; verification checks
them and reports that the paths through the unknown need a rescan once it
is resolved; the console says *resolve the unknowns listed, then rescan: the
fix may need more steps once they are known*. AWS managed policies whose
document is known are detached instead (identity, revoke; one change for
every edge they grant).

### 9.4 Output — the patch

- **Terraform** (`internal/patch`): edits are placed at byte ranges that
  `hclsyntax` locates and spliced in; everything else is kept byte for byte —
  line endings (CRLF or LF), a UTF-8 BOM, comments, spacing — and new text
  uses the file's line ending and indentation. Three ways of writing a policy:
  `jsonencode({...})` (HCL object), a heredoc (JSON at offsets a small JSON
  parser records; interpolations inside strings are resolved), and
  `data "aws_iam_policy_document"` (statement blocks, `=` aligned as
  `terraform fmt` does). Every edited file is parsed again; a patch that does
  not parse is an error, never output. A fuzz target (`FuzzPatchTerraform`)
  runs the patcher on arbitrary HCL: it patches (and the result parses) or
  refuses.
- **References, never invented names**: an ARN of a resource the same
  module defines is written as its reference (`aws_kms_key.pii.arn`,
  `"${aws_s3_bucket.b.arn}/*"`); a real ARN of the input is written as is; an
  ARN Terraform knows only after apply, outside the module, is a TODO. A test
  checks that every ARN a fix writes is one of the input.
- **Variables, modules, `for_each`**: a value that comes from `var.X` in a
  module names the module call's input (file:line) in a TODO; a statement
  added to, or removed from, an instance of `count`/`for_each`, or added in a
  module used by several calls, is a TODO (it would change every instance).
- **Snapshots and live accounts**: the complete JSON policy document, ready
  for `aws iam put-role-policy` (or `delete-role-policy` when no statement
  remains), never a Terraform diff; level 2 writes it into a copy of the
  snapshot.
- **Kubernetes manifests**: line edits at the lines a YAML parser locates
  (remove `hostNetwork`, `type: ClusterIP`).
- **UNKNOWN paths are not patched**: the remediation lists what would decide
  them (a context key to assume, a value a plan resolves, a precondition).

### 9.5 `clapa remediate`

`clapa remediate [input flags] FINGERPRINT` shows the plan, both
verifications and the patch, and changes nothing. `--write` applies a fix
verified on both levels, **narrow fixes only**; a revoke (it removes a grant
written on purpose) needs `--allow-revoke`, and the console marks it "this
removes an explicit grant; confirm it is not needed". It refuses to write into
a git tree that is not clean, or whose state it cannot tell (`git status
--porcelain`), unless `--force`; it refuses a file changed since the scan.
Exit codes: 0 a verified fix (shown or written), 1 no verified fix (UNKNOWN,
no fix within the constraints, TODO, rejected), 2 usage or `--write` refused,
4 internal. `internal/cli` runs `git` for this check only (`os/exec`).

---

## 10. LLM integration (Phase 7)

Off by default; enabled only with `--llm <provider>` plus an API key. Provider is
deferred to Phase 7. The generic interface:

```go
type Explainer interface {
    Explain(ctx context.Context, req ExplainRequest) (Explanation, error)
}
// ExplainRequest carries only structured evidence from pkg/schema
// (already redacted and optionally pseudonymised); never raw files.
```

Allowed: natural-language explanation of an already-computed finding, executive
summary. Never: verdicts, scores, fixes. Redaction via `internal/redact` (≥ 40 secret
formats + false-positive corpus; shared with log redaction). `--llm-redact-identifiers`
pseudonymises account IDs, ARNs and names with a reversible mapping kept locally.
Structured output against a JSON schema, timeout, retries, token cap; any failure ⇒
template text plus a note that the fallback happened. Output labelled "AI-generated
explanation" and HTML-escaped like any other untrusted string.

**Implementation (Phase 7).**

- Packages: `internal/llm` (pure: `Evidence`, `Prepare` = redact then
  pseudonymise, `Explain` = ask, validate, restore, strip control characters,
  or fall back to `Template`), `internal/llm/pseudonymize` (reversible tokens
  `arn-0001`, `account-0001`, …), `internal/llm/claude` (io; the only package
  that imports the provider SDK).
- Provider `anthropic`: `anthropic-sdk-go/v2` v2.7.0, Messages API, model
  `claude-opus-5-5` unless `--llm-model`; structured output with a closed JSON
  schema (`summary`, `attack`, `fix`); timeout 2 minutes per call, 2 retries
  (429, 5xx, connection errors), token cap 4000; a refusal is re-served by the
  API's default fallback model; `stop_reason` refusal or max_tokens is a failure.
- CLI: `scan --llm anthropic [--llm-model M] [--llm-redact-identifiers]`
  explains every attack-path finding and writes `executive_summary`;
  misconfigurations are explained by their rule's rationale, not sent.
  `clapa explain [scan input flags] [--llm …] FINGERPRINT` explains one
  finding of any kind (console or json); without `--llm` it prints the
  template text. The key comes from `ANTHROPIC_API_KEY` only; `--llm` without
  it is a usage error (exit 2) naming the variable.
- Report: `finding.explanation` and `executive_summary`
  (`schemas/report.v1.schema.json` `$defs/explanation`): `ai_generated`,
  `model`, `note` (why the template was used). Console and HTML head each one
  with `Explanation.Label()`; the HTML puts it in an `<aside>`, escaped.
- What the engine reads back: nothing. Removing every explanation from an
  explained report gives the unexplained report byte for byte
  (`TestExplainedReportMatchesTheSchema`).
- Tests use a fake provider (an `httptest` server for the SDK client, a stub
  `Explainer` for the CLI); no test calls the real API.

---

## 11. CLI and output

Commands: `scan`, `explain`, `graph`, `remediate`, `rules list|show`,
`collect-snapshot`, `doctor`, `version` (spec §11.1).

**Phase 6 commands and flags.**

- `clapa collect-snapshot --out DIR`: live, read-only, writes a new bundle.
  Exit 3 when calls failed, and no bundle when nothing was collected.
- On `clapa scan`:
  - `--live-aws` with the AWS flags (`--aws-profile`, `--aws-region`,
    `--aws-assume-role`, `--aws-external-id`, `--aws-concurrency`,
    `--aws-call-timeout`);
  - `--aws-snapshot DIR` (was `--snapshot`);
  - `--live-k8s CONTEXT[=CLUSTER]`, `--k8s-eks NAME`, `--kubeconfig`,
    `--insecure`;
  - `--ignore FILE`, `--baseline PREVIOUS.json`.
- `remediate` refuses live input, since it has no files to patch: run
  `collect-snapshot` and remediate the snapshot.

The console prints the coverage notes a reader must see before trusting the
result as `WARNING:` lines:
- a managed-policy snapshot that is incomplete;
- service coverage that is incomplete or unknown;
- TLS verification turned off;
- expired suppressions.

**Flag — `doctor` vs "no os/exec".** `doctor` does not run external binaries; it
reports the Go runtime, kubeconfig/AWS config presence, and probes read-only API
permissions (`sts:GetCallerIdentity`, `iam:SimulatePrincipalPolicy` when allowed).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings at or above `--fail-on`, **and** coverage complete within tolerance |
| 1 | Findings at or above `--fail-on` |
| 2 | Usage or configuration error |
| 3 | Scan incomplete: coverage gaps above tolerance, or nothing collected |
| 4 | Internal error (including recovered panics) |

**Decision — precedence when several apply:** 4 > 2 > 1 > 3 > 0. Rationale:
confirmed findings are actionable even when coverage is partial; incompleteness only
undermines a *clean* result. The report always states the coverage either way.

**Flag — default tolerance.** Exit 0 requires "coverage complete", so the default
gap tolerance is **0** for every gap kind, including `Unresolved` Terraform values.
Users can raise it per gap kind in `clapa.yaml`; the report shows the tolerance used.

### Formats

- **JSON** — `schema_version`, published JSON Schema in `schemas/`, validated in
  tests; tool version, rule-catalog version, input digests (sha256), coverage,
  findings, graph stats, timing (behind `--timestamps`, §3.4).
- **SARIF 2.1.0** — `physicalLocation` to TF/K8s lines (`uriBaseId`
  `%SRCROOT%`, the scan root), attack paths as `codeFlows` (the entry, then one
  location per hop; Phase 7), our fingerprint in `partialFingerprints`.
  *Status:* the structure is tested (`internal/report/sarif`); validation
  against the official OASIS schema needs the schema vendored into testdata and
  is not done yet.
- **HTML** — single file, `html/template`, assets via `embed`, strict CSP
  (`default-src 'none'`, hashed inline script/style), data embedded as escaped JSON;
  test with a resource named `<script>`. Implemented in Phase 7
  (`--format html`, `internal/report/htmlreport`): the page is rendered in
  full by the template (findings, paths, the cut with each step's side, kind
  and cost, resolve steps and the pending note, the alternative, also_fixes,
  coverage, intended access, triage, rules); the script only filters the
  findings already in the page (severity, status, text) and never writes
  markup; no network, no timestamp (two renderings are identical). Tests
  (`htmlreport_test.go`): hostile names (`<script>`, an attribute breakout, an
  early `</script>`) stay text, the policy hashes exactly the page's style and
  script, the data block is the report.
  After the first review: a **path view** per finding (and for the
  worst-case path, in `<details>`): static SVG laid out in Go and rendered
  by `html/template`, one box per node (workload, service account, role,
  key, data), one arrow per edge with its kind, wrapped after four boxes;
  the cut edge dashed and marked ✂, a resolve step dotted and marked `?`;
  no script draws it, names are escaped text, colours are CSS classes (the
  policy does not change), the same report gives the same bytes. The
  report states its **scanned inputs** (each path, or live accounts and
  regions, or cluster by key, with the SHA-256 of what was read, schema
  `inputs`), the tool and rule-catalog versions, and, with `--timestamps`,
  when it was made (`generated_at`). `scan --fixes` runs the remediation
  of every path finding (the same plans, patches and two-level
  verification as `clapa remediate`) and puts it in the report
  (`remediation`: each fix's `fix_strategy`, `root-cause` or `mitigation`
  with "blocks this path only; the broad grant remains", its changes,
  `verified_in_memory`, `verified_on_patched_files`, the diff, the order
  of §9.2 and its advice); the page shows the diff in `<details>`, its
  lines coloured by CSS only. Printing (`@media print`, and the script
  opening every `<details>` before printing): filters hidden, each
  finding on a new page, black and white with dashes and marks for what
  colour showed. `docs/examples/report-scenario-01.html` and
  `report-scenario-22.html` are made by the tool (`scan --fixes --format
  html`); `TestExampleReports` fails when they are not what it makes now.
  After the second review: a derived read is drawn as what it stands for
  (the read to the data, the decrypt down to the KMS key, the key
  protecting the data), with the marks on the edge the fix changes; a cut
  edge off the drawn path (the escalation of a dominated path merged into
  the cut) is drawn as a branch, so every fix step is an edge of the
  drawing (`TestEveryFixStepIsDrawnWithItsMark`). Each finding has one fix
  section: "Recommended fix" (the first fix of §9.2: strategy, what
  changes in a sentence, verification, the patch), "Other options", and
  "How this fix was chosen" (closed: the cut's edges, sides, costs, other
  sides, alternative, `also_fixes`, uncuttable edges); a cut of resolve
  steps only starts with "Resolve first", then the known alternative. A
  suggestion is shown grey ("suggestion, not verified"), never as a failed
  verification. Attack paths (path rules) come before misconfigurations
  (posture rules), each by severity then score; the summary counts them
  apart.
- **Console** — concise by default, `-v` for detail, `NO_COLOR`, plain when not a
  TTY. **All untrusted strings are stripped of control characters** before printing
  (terminal escape injection via resource names; see THREAT_MODEL.md).
- JUnit and Markdown for CI systems.

Logging: `slog`, `--log-format json`, a redacting handler (keys and value patterns
from `internal/redact`), `--debug` for stack traces, otherwise one-line errors with
a hint.

---

## 12. Delivery phases

| # | Phase | Gate |
|---|---|---|
| 1 | Design docs, threat model, skeleton, CI on empty tests | lint + vet + tests + archtest + govulncheck green |
| 2 | Model + evaluator, ≥ 150 cases, fuzz, properties | ≥ 95% branch coverage (gobco) on `eval` |
| 3 | Offline collectors + normalizers | golden fixtures, no ID collisions |
| 4 | Graph, paths, rules, scoring, findings, JSON/SARIF/console | every scenario matches its expected.json, benchmarks within target |
| 5 | Remediation + verifier + patches | diff → rescan → exit 0 on fixtures |
| 6 | Live collectors + `collect-snapshot` | fakes, smithy stubs, LocalStack/kind jobs |
| 7 | HTML, LLM layer, docs, packaging | spec §15 definition of done |

### 12.0 Phase 4 status

Done: access graph (`internal/graph`, CSR), access builder (`internal/access`:
RUNS_AS, CAN_ESCALATE[k8s-token|rbac|iam:passrole:<service>|iam:update-trust|
iam:modify-policy], ASSUMES[irsa|projected|minted|minted-self|pod-identity|sts],
MAPS_TO (aws-auth, access entries, access policies), NODE_ROLE, CAN_READ,
CAN_DECRYPT[for J], CAN_READ_PLAINTEXT), path search and weighted min-cut
(`internal/paths`), scoring (`internal/scoring`), the ten rules of §8.1
(`internal/rules/...`), fingerprints, suppressions, baseline and exit code
(`internal/findings`), the versioned report (`pkg/schema` `clapa-report/v1`)
with console, JSON and SARIF 2.1.0 writers, the CLI (`clapa scan | rules list |
rules show | version`), benchmarks and `bench.yml` (base vs head on one runner,
`benchstat` for people, `tools/benchgate` for the decision: median > +20% and
Mann-Whitney p < 0.05).

`expected.json` comparison: `TestExpectedFindings` passes only while the
engine's differences from the hand-written files are exactly those listed in
`internal/app/testdata/open_mismatches.txt`. Groups A–F found in the Phase 4
reviews are resolved and the list is empty; Phase 4 was approved with zero
differences. The expected files are not edited to match the engine.

**Phase 5, step 1 (done first, before any other Phase 5 work).** Every expected
finding with a cut states the side, fix kind and cost of its chosen fix
(`fix`), of the other sides of the cut edges (`other_side_fix`) and of the
alternative's fix (`alternative_fix_detail`), empty lists included; the golden
test fails on an expected cut that omits them. The values were derived by hand
from each fixture's policies (comments in `tests/fixtures/expected_source.py`)
and then compared: no difference. Before this, the change of scenarios 13 and
14 from cost 1 to 3 in the fourth Phase 4 review passed unnoticed; now raising
the revoke surcharge from 2 to 3 alone fails 28 comparisons in 18 variants.

Not built in Phase 4. Unlike an unknown value, these produce no UNKNOWN: the
engine is silent about them. Every scan therefore lists them as coverage notes
(`not-modelled`, `app.notModelled`), so a clean result is not read as "no
risk":

| Missing | Effect | When |
|---|---|---|
| ~~Secrets Manager, SSM SecureString and Kubernetes Secrets as targets~~ | done in Phase 6 (§7.3); what is still not modelled about them is listed in every report | — |
| ~~Suppression file and `--baseline`~~ | done in Phase 6 (§8) | — |

### 12.0b Phase 5 status

Done: remediation (`internal/remediate`: edits per edge and side,
`Apply`), two-level verification (`internal/verify`, `app.Remediate`), the
patcher (`internal/patch`: three Terraform policy forms, attributes, YAML,
snapshot JSON), `clapa remediate` with the `--write` safety rules, the
`EXPOSED_TO` edge (cost 20, revoke), IMDS fixes by hostNetwork, the
UNKNOWN "what is missing" output, the patch fuzz target. Every vulnerable
scenario's fix verifies on both levels except 10 (UNKNOWN) and 13 (module
input TODO), §9.3.

**Phase 5 review (strategies).** Root-cause and mitigation fixes (§9.2),
`CLAPA-POST-008` (catalog 1.1.0, pinned by `TestCatalogVersion`), the
new-bucket Block Public Access default for plans (§4.7), and scenario 1b.
Fixtures 01b, 06, 09 and 10 now state Block Public Access for every bucket, so
no scan of them has a coverage gap. After the first fix, the scan of each
vulnerable scenario exits 0 only when nothing else is reported at `high`: 01b
(verified root cause) and 08 do; after a mitigation `CLAPA-POST-008` keeps the
exit at 1 (01, 06, 07, 12, 16, 17), as do the findings the fix is not about
(`CLAPA-POST-001` in 04, 04b, 05; `CLAPA-POST-002` in 09); 10 is UNKNOWN; 13 is
a TODO; 14's fix is a policy document for the account; 16 keeps its parse
gaps by design.

### 12.0c Phase 6 status

Done:

- **Collectors:** the live AWS collector (§4.4); `collect-snapshot` and the
  bundle writer (§4.3); the live Kubernetes collector (§4.5).
- **CLI:** the live and snapshot flags, suppressions and baseline (§8, §11);
  `docs/PERMISSIONS.md`.
- **Cluster identity by ARN** (§5, scenario 18).
- **Targets:** Secrets Manager, SSM SecureString and Kubernetes Secrets
  (§7.3, scenarios 19–21).
- **Reports:** the managed-policy coverage note and its console warning; the
  per-service coverage notes.
- **Tooling:** `tools/depage` with its security exceptions
  (`tools/depage/allow.yaml`), in CI at the commit time; Dependabot cooldown of
  14 days.
- **CI:** `integration.yml` (LocalStack, kind).

Every scenario matches its `expected.json`. Scenarios 18–21 matched on the
first run of the engine after their files were written. Every vulnerable
scenario's fix verifies on both levels, except 10 (UNKNOWN) and 13 (module
input), as before.

Decided while implementing:

- **LocalStack image.** LocalStack's current images need an account token, so
  the job pins the last image that runs without one (§4.4).
- **Rotation of AWS managed keys.** The collector does not invent the answer;
  the normalizer applies it as a documented default (§4.7), so a snapshot file
  never claims a call that was not made.
- **Names in the bundle.** Name escaping (`!x` for an upper-case letter) keeps
  two names that differ only in case apart on case-insensitive file systems.

### 12.1 Known constraints carried between phases

| Constraint | Effect today | Must be resolved by | Plan |
|---|---|---|---|
| **AWS managed policy snapshot has 3 policies** (`AdministratorAccess`, `AmazonS3FullAccess`, `AmazonS3ReadOnlyAccess`) — recorded after the Phase 3 review | every other AWS managed policy attached to a role is an unknown Allow + unknown Deny and a `not-modelled` gap: never "no permissions", but paths through such roles are UNKNOWN (confidence low) instead of decided | **before any scan of a real account** (live collectors meet real accounts, where most roles use managed policies). Phase 6 itself is tested on fakes, LocalStack and kind only | `tools/refresh-managed-policies` is **ready and tested** (546ec63): it lists every AWS-owned policy (`iam:ListPolicies`, `Scope=AWS`) and fetches each `DefaultVersionId` (`iam:GetPolicyVersion`), nothing else; `--profile` selects the profile, the SDK reads its credentials; the snapshot (format v2) records the date, partition, count and each default version, sorted, byte-for-byte deterministic. The refresh was **deferred on 2026-11-21**: only a valid profile is missing (the one tried was not found in `C:\Users\<user>\.aws\{config,credentials}`). Run: `go run ./tools/refresh-managed-policies --profile <profile>`, then review the diff and the scenarios whose results change, and commit the snapshot alone. Until then a live or snapshot scan reports every attached managed policy that is not in the snapshot (Phase 6) |
| ~~**Kubernetes Secrets mounted into pods**~~ — **done in Phase 7**: `CAN_READ_PLAINTEXT[mount]` from each workload to each Secret its pod spec names, and `CAN_READ_PLAINTEXT[pod-create]` from each subject that may create pods in the namespace (§7.2); scenario 23 derived by hand before the engine ran, no difference; the mount fix is generated and verified on both levels | admission policies that could reject such a pod are not read (`not-modelled` note) | — | — |
| ~~**S3 account-level Block Public Access**~~ — **done in Phase 7**: collected (live, snapshot, Terraform) and combined with the bucket's, the most restrictive applies (§6, S3 Block Public Access); variant `12_public_bucket/account_block` derived by hand before the engine ran, no difference | a snapshot written before Phase 7 has no account setting (a `not-modelled` note per account) | — | — |
| **AWS RAM shares of advanced SSM parameters** — Phase 6 review | cross-account access is evaluated from the resource policies collected; a RAM share not reflected in them is missed | **priority 3**: before multi-account parameter sharing is in scope | collect RAM resource shares (`ram:ListResources`, `ram:GetResourceShareAssociations`) for parameters |
| Coverage tolerance counts gaps | plan gaps for provider-computed attributes (`arn`, `id`, …) are recorded; the exit-code tolerance does not exist yet | Phase 5 (exit codes) | count only gaps that a decision used (section 4.6, "Provider-computed attributes") |

Workflows that only make sense once their subject exists (`bench.yml` — Phase 4,
`integration.yml` — Phase 6, `release.yml` + `.goreleaser.yaml` — Phase 7) are
added in those phases rather than as placeholders.

### 12.2 Deferred work (recorded at the Phase 4 approval; after Phase 5)

| # | Work | Why it waits / what done means |
|---|---|---|
| 1 | **Report JSON Schema** — **done** (after Phase 5): `schemas/report.v1.schema.json` (draft 2020-12) describes `clapa-report/v1` from `pkg/schema`, every object closed, with the Phase 4/5 meanings (`alternative_fix`, `alternative_fix_detail`, `fix_kind`, `fix`, `other_side_fix`, `shared_fix_possible`). `TestEveryReportMatchesTheSchema` validates the JSON report of every fixture variant and mode; `TestSchemaDescribesTheGoTypes` fails on a field in the Go types and not the schema, or the other way. | — |
| 2 | **Independent comparison with the previous tool** — **done** (2026-11-21): docs/COMPARISON_PREVIOUS_TOOL.md. Its four samples, scanned by both tools on separate copies outside this repository: no sample grants an S3 read, so CLAPA reports no path where the previous tool reports decrypt as exfiltration; one CLAPA defect found and fixed (`CLAPA-POST-001` missed a wildcard scoped to one namespace; rule 1.0.1). | — |
| 3 | **Real console output** of scenarios 01, 04b and 10, shown in review as the CLI prints it (not reconstructed). | Done: the three outputs captured from `clapa scan` on the fixtures, after Phase 5's fields are final. |
| 4 | **`.clapa-ignore.yaml` and `--baseline` in the CLI** — **done** (Phase 6, 92e5612): both wired, with the config errors of §8, expired suppressions re-firing, and tests through the CLI (§8). | — |
| 5 | **Secrets Manager, SSM SecureString and Kubernetes Secrets as targets** — **done** (Phase 6, d3b6405 then 5bff8d3): collectors, normalizers and read semantics (§7.3, §7.2); scenarios 19–21 with their expected files committed by hand before the engine read them. | — |

## 13. Test fixtures

`tests/fixtures/<NN_scenario>/{vulnerable,fixed}/` + `expected.json` (findings by
rule ID + fingerprint). Immutability: the golden runner copies each fixture to
`t.TempDir()` before anything runs; CI runs `git diff --exit-code -- tests/fixtures`
after the test job; fixtures are LF-only via `.gitattributes`.

Scenario 13 (module + `for_each`) needs a real plan JSON. It is generated with
Terraform using fake credentials and the AWS provider's `skip_*` validation
settings, committed, and regenerated only by `scripts/generate-fixture-plan.ps1`;
CI never needs Terraform. *Status (Phase 3 review):* the hand-written plan was
replaced by real output (Terraform 1.17.1, `hashicorp/aws` 6.73.0). The real
format showed two differences the hand-written file hid — instance references
without attribute and provider-computed `managed_policy_arns`/`inline_policy` —
both fixed in the reader and normalizer (section 4.6). The module uses the
common `for_each = toset(...)` with `aws_iam_role.r[each.value]`, resolved
exactly once the configuration shows the set; the bucket states SSE-S3
explicitly (§13.1).

*Phase 3 status:* every variant has `normalized.golden.json` (inventory, gaps,
entry points; and `normalized.static.golden.json` when a plan is present),
checked by `internal/app/golden_test.go`, which also runs each scan twice and
requires byte-identical output. `expected.json` (findings) is added in Phase 4
together with the rules that produce findings. See `tests/fixtures/README.md`.

### 13.1 Read-permission audit (decided after Phase 1 review)

Every scenario whose expected result is "path found" must actually grant the
read. By §7.3, a path to KMS-protected data needs **both** `CAN_READ` and
`CAN_DECRYPT`; to SSE-S3 / unencrypted data, `CAN_READ` alone. A fixture whose
only defect is a missing read permission would test nothing. Common to all
fixtures unless stated: every KMS key's policy contains the default statement
that delegates to the account root (`arn:aws:iam::<acct>:root`, `kms:*`), so IAM
policies can grant `kms:Decrypt` (KMS Developer Guide › "Default key policy").
Encryption type of every jewel bucket is stated explicitly in the fixture
(`aws_s3_bucket_server_side_encryption_configuration`), never left unknown.

### 13.2 Scenarios

"Read grant" = what gives `CAN_READ` (and `CAN_DECRYPT` where needed) on the jewel.

| # | Scenario | Read grant in the vulnerable variant | Expected (vulnerable) |
|---|---|---|---|
| 1 | IRSA → role → `kms:Decrypt` on `*` → CMK → PII bucket (SSE-KMS) | role policy: `s3:GetObject` on `arn:aws:s3:::<pii>/*` **and** `kms:Decrypt` on `*` | path found (`CAN_READ` + `CAN_DECRYPT` → `CAN_READ_PLAINTEXT`) |
| 2a | (split in the Phase 4 review) Two buckets, two keys: **A** = legitimate payments bucket (key A), **B** = PII bucket (key B), both SSE-KMS. A has an **S3 Bucket Key**, so S3's KMS encryption context is A's bucket ARN; the role decrypts key A with `StringEquals kms:EncryptionContext:aws:s3:arn = arn:aws:s3:::A`. `clapa.yaml` declares A as `intended_access` | read + decrypt on A only | **no path to B**; intended access to A **verified** |
| 2b | As 2a, **without** a Bucket Key (stated `bucket_key_enabled = false`): the context is the object ARN, and the grant uses `StringLike … = arn:aws:s3:::A/*` | read + decrypt on A only | no path to B; intended access to A **verified** |
| 2c | Negative case: no Bucket Key, but the grant uses `StringEquals` on A's bucket ARN, which S3 never sends without a Bucket Key | none that works | no path to B; the declared intended access is **not satisfied**, an explicit result of the report (fixed: the `StringLike` form of 2b) |
| 3 | Role has `s3:GetObject` on PII bucket B (SSE-KMS, key K) and `kms:Decrypt` on K with `kms:EncryptionContext:aws:s3:arn` = a **different** bucket's ARN | `s3:GetObject` on `B/*` is present on purpose, so the encryption context is the only deciding factor | **no path to B** (`CAN_READ` yes, `CAN_DECRYPT[for B]` no) |
| 4 | Trust `StringLike :sub = system:serviceaccount:*:*`; `tools/default` carries an IRSA annotation for a low-privilege role (so its pods hold an STS token) | role policy: `s3:GetObject` on PII bucket (SSE-KMS) + `kms:Decrypt` on its key | path from **every** SA's workload → role → jewel; plus posture finding "wildcard OIDC sub" |
| 5 | Trust with `:aud` only, no `:sub` | same as 4 | same as 4 (any SA of that issuer) |
| 4b | (added in the Phase 4 review) A service account **without** an IRSA annotation whose Role may `create pods` in its own namespace; `payments-api` trusts `StringLike :sub = system:serviceaccount:*:*` | role policy as 4 | path via `CAN_ESCALATE` (its own token, then a minted STS token): the annotation is not a security boundary |
| 6 | SA role in account A → `sts:AssumeRole` on `*` → role in account B with `AdministratorAccess`, trusting A's root; jewel: PII bucket in B (SSE-KMS, key policy delegates to B's root) | `AdministratorAccess` (`*` on `*`) gives `s3:GetObject` and `kms:Decrypt` in B | cross-account path (identity side in A and trust in B both allow) |
| 7 | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` on a role with read on the jewel | passed role: `s3:GetObject` on PII bucket (SSE-KMS) + `kms:Decrypt` on its key | escalation path via `CAN_ESCALATE` to the passed role, then to the jewel. **Flag:** `CreateFunction` alone does not execute code; the rule requires an execution primitive (`InvokeFunction`, `CreateEventSourceMapping`, or `CreateFunctionUrlConfig`). The fixed variant drops `InvokeFunction` *and* scopes `PassRole`; a test checks that `PassRole + CreateFunction` alone is reported as a lower-confidence escalation |
| 8 | RBAC `create pods` in namespace N; SA `s` in N has IRSA role R | R: `s3:GetObject` on PII bucket (SSE-KMS) + `kms:Decrypt` on its key | escalation: entry workload's SA → (`CAN_ESCALATE`, create pod as `s`) → R → jewel |
| 9 | `hostNetwork` pod + IMDSv1 → node role → `s3:GetObject` on `*` | node role: `s3:GetObject` on `*`; jewel bucket is **SSE-S3**, so no decrypt is needed (keeps the spec's "`s3:GetObject` on `*`" literal) | path with `NODE_ROLE` precondition (satisfied: hostNetwork, IMDSv1) |
| 10 | KMS key policy grants `kms:Decrypt` to `{"AWS":"*"}` with `aws:PrincipalOrgID`; bucket SSE-KMS with that key | workload role: `s3:GetObject` on the bucket; decrypt comes only from the key policy | path is **UNKNOWN** (unconfirmed, `confidence: low`) unless `aws:PrincipalOrgID` is configured; with a matching org ID configured → path found; non-matching → no path |
| 11 | Same grants as scenario 1, plus a permissions boundary with an explicit `Deny s3:GetObject` | as scenario 1 (so only the boundary blocks) | **no path**; evidence names the boundary statement |
| 12 | Bucket policy `Principal "*"`, `s3:GetObject`, no conditions; Block Public Access off; bucket **SSE-S3** | the bucket policy itself (anonymous read; SSE-KMS would not be readable anonymously) | path internet/anonymous → jewel (public read) |
| 13 | Module + `for_each` → 3 IRSA roles for 3 SAs | each role: `s3:GetObject` on an SSE-S3 PII bucket | plan mode: 3 roles resolved, 3 paths; static mode: role ARNs/policies `Unresolved`, findings `confidence: low`, listed in coverage, exit 3 at default tolerance |
| 14 | Same role name (and same bucket-name suffix) in two accounts (snapshot); one cluster runs `apps/app-a` (IRSA role `app` of 111122223333) and `apps/app-b` (cross-account IRSA role `app` of 444455556666) | each role reads its own account's SSE-S3 bucket | two distinct node IDs, two findings with distinct fingerprints; no edge and no path crosses between the accounts to the same-named resources (`no_edges`) |
| 15 | Empty directory | — | exit 3, no "secure"/"0 findings" claim |
| 16 | One malformed YAML file and one malformed HCL file next to a valid copy of scenario 1 | as scenario 1 in the valid files | both errors reported with `file:line`; the scenario-1 path is still found (proves the scan continued) |
| 1b | Scenario 1 plus the API's legitimate use, declared in `intended_access`: it reads the receipts bucket (SSE-KMS, its own key) | role policy as scenario 1 plus `s3:GetObject` on the receipts bucket | the PII path as scenario 1; remediation: a **verified root-cause** fix first (`kms:Decrypt` narrowed to the receipts key), then the mitigation; fixed: that root cause applied |
| 17 | Scenario 1 through **EKS Pod Identity** (added after the Phase 3 review): `aws_eks_pod_identity_association` payments/api → role trusting `pods.eks.amazonaws.com` for `sts:AssumeRole` + `sts:TagSession`, pinned by `aws:RequestTag/kubernetes-namespace` and `…/kubernetes-service-account`; `eks-pod-identity-agent` add-on | as scenario 1 | as scenario 1: the path, with the association and trust decision as evidence |
| 18 | (Phase 6) Two EKS clusters named `prod` in one account, eu-west-1 and us-east-1; each has `apps/app` bound by IRSA to its own role (`app-eu`, `app-us`), each reading its region's SSE-S3 PII bucket | each role: `s3:GetObject` on its own bucket | two paths with distinct fingerprints; no edge between the clusters (`no_edges`); no coverage gap (exit 0) |
| 19 | (Phase 6) Scenario 1 with a **Secrets Manager** secret (`DataClass: secret`) under a customer managed key | `secretsmanager:GetSecretValue` on the secret's ARN + `kms:Decrypt` on `*` | path, 810 critical; cut: the broad decrypt |
| 20 | (Phase 6) Scenario 1 with an **SSM SecureString** parameter under a customer managed key | `ssm:GetParameter` on the parameter's ARN + `kms:Decrypt` on `*` | path, 810 critical; cut: the broad decrypt |
| 21 | (Phase 6) A **Kubernetes Secret** (`DataClass: secret`); `payments/ci` may `get secrets` in `payments`, its token mounted by default | RBAC `get secrets` | `CLAPA-PATH-001` (its own token, then the RBAC read: direct access, §7.2), 360 medium; cut: the token mount (revoke, 5), alternative the RBAC read (5) |
| 23 | (Phase 7) The same Secret read **without an RBAC read**: `payments/api` names it in an env var and a volume (token not mounted); `payments/ci` may `create pods` in `payments`, its token mounted by default | `CAN_READ_PLAINTEXT[mount]`; `CAN_READ_PLAINTEXT[pod-create]` | `CLAPA-PATH-001` api, 400 medium, cut the mount (workload, revoke, 5), no alternative; `CLAPA-PATH-001` ci-runner, 360 medium, cut the token mount (5), alternative the pod-creation grant (rbac, 5); fixed: api names a non-jewel Secret, ci may only read pods |
| 22 | (Phase 6 review) One pair, two findings: `apps/app` → `role/app` reads the PII bucket, its decrypt conditioned on an unresolved variable; `role/app` may assume `role/ops`, which may rewrite its own policy. Variants: `fixed` (role/ops lists only), `dominance` (role/app decrypts unconditionally and rewrites its own policy; no role/ops) | `s3:GetObject`, `kms:Decrypt` (conditioned), `sts:AssumeRole` on role/ops; role/ops `iam:PutRolePolicy` on itself | vulnerable: `CLAPA-PATH-001` (unconfirmed, 291 medium, cut: resolve the variable) and `CLAPA-PATH-002` (confirmed, 235 low); fixed: the direct finding only; dominance: one `CLAPA-PATH-001` whose cut breaks the dominated escalation too (decrypt 1 + escalation 4) |

Fixed variants remove exactly the cause the scenario tests (e.g. scenario 1 scopes
`s3:GetObject` and `kms:Decrypt` to the workload's legitimate bucket and key, with an
encryption-context condition, so nothing reaches the PII bucket; scenario 4 pins
`:sub`), and their `expected.json` must show the targeted path gone.

## 14. Security of the tool itself

See `docs/THREAT_MODEL.md`. Summary of controls: no `os/exec` except §4.1, no
`unsafe`, no `text/template`, input size and depth caps, symlink and path-traversal
protection on every input and output path, `go.sum` committed, `GOFLAGS=-mod=readonly`
in CI, Dependabot, `govulncheck`, `gosec`, `gitleaks`, GitHub Actions pinned by
commit SHA, no network egress except the cloud APIs being read and the explicitly
enabled LLM provider.

**Decision — Dependabot instead of Renovate.** The plan mentioned `renovate.json`;
Dependabot needs no GitHub App installation and covers `gomod` and
`github-actions`. Either satisfies the spec.

## 15. Definition of done — measurement notes

- "CI green on the two latest Go releases" is re-evaluated at each release.
- `-race` requires cgo; on Windows that needs a C toolchain (CI runners have one; a
  developer machine may not — `task test:norace` exists for that case and is never
  used by CI).
- Fuzz targets run ≥ 5 minutes each in a scheduled/nightly job, not on every PR.

## Appendix A — Toolchain pinned in Phase 1 (verified 2026-11-20)

| Tool | Version |
|---|---|
| Go | 1.27.4 (local), CI 1.26.x / 1.27.x, `go.mod` `go 1.26.0` |
| golangci-lint | v2.15.0 |
| gofumpt | v0.12.0 (via golangci-lint formatters) |
| go-task | v3.54.0 |
| lefthook | v2.2.2 |
| govulncheck (`golang.org/x/vuln`) | v1.10.0 |
| gitleaks | v8.30.1 |
| actions/checkout | v7.0.1 @ `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/setup-go | v7.1.0 @ `d8cbb8045d7f43706b9177cceb36c1f91a6644d5` |
| golangci/golangci-lint-action | v9.3.0 @ `ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a` |
| actions/upload-artifact (Phase 2) | v7.0.2 @ `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| gobco (Phase 2) | v1.3.4 |
| sigs.k8s.io/yaml (tests, Phase 2) | v1.6.0 |
| pgregory.net/rapid (tests, Phase 2) | v1.3.0 |
