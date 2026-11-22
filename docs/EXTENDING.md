# Extending darb

How to add a rule, an input, a report format or an LLM provider without
breaking the guarantees the tests hold: determinism, UNKNOWN never counted as
secure, read-only collection, and the package layering.

Before any change, read the parts of [DESIGN.md](DESIGN.md) it touches. Two
rules apply to every extension:

- **Layers.** Each package has a row in `internal/archtest/layers.go`: its
  layer (pure, core, io, entry) and what it may import. A new package needs a
  row; run `task gen` to regenerate the depguard rules and the table in
  DESIGN.md §3.2. `internal/archtest` fails on an import the table does not
  allow, in code or in tests (`TestInternal`).
- **Expected results come first.** A scenario's `expected.json` is derived by
  hand in `tests/fixtures/expected_source.py` (with the score arithmetic in
  comments) **before** the engine runs on it. When the engine disagrees, the
  difference goes to `internal/app/testdata/open_mismatches.txt` and is
  investigated; the expected file is never changed to match the tool.

## A posture rule

A posture rule is a pure function of `rules.Input` (the inventory, the
graph, the entry points and jewels) that returns hits.

1. Add the ID constant and a `rule` to `Rules()` in
   `internal/rules/posture/posture.go`: `meta(id, title, rationale, base,
   techniques, references, failing, passing)`, a confidence and the check.
   - `rationale` says what an attacker gains, in one paragraph;
   - `base` is one of the `scoring.Base*` levels (SCORING.md §2);
   - `references` link the AWS or Kubernetes documentation the check
     relies on — a rule without a documented basis is not added;
   - `failing` / `passing` name fixture variants on which the rule must and
     must not fire (`TestRuleCatalogMetadata` checks they exist).
2. The check returns a `hit` per resource: its ARN or Kubernetes identity,
   its `SourceLocation`, the evidence strings, and the documented defaults it
   relies on (`model.Default*`, DESIGN.md §4.7). When an input value is not
   known, do not report it as a pass: either report the hit with lower
   confidence or record a coverage gap.
3. Unit-test it in `posture_test.go` with a hand-built inventory, including
   the UNKNOWN case.
4. Bump `catalog.Version` (minor for a new rule, patch for a fix of an
   existing one, with the rule's own version) and add the new set to
   `pinned` in `internal/rules/catalog/catalog_test.go`. A rule's major
   version is part of its fingerprints: change it only when old fingerprints
   must stop matching.
5. Add the expected findings to `expected_source.py`, run
   `python tests/fixtures/expected_source.py`, then `go test ./internal/app`.

## A path rule or a new edge

Path rules (`internal/rules/pathrules`) select entry–jewel pairs and use the
shared search and min-cut (`internal/paths`). Most new attack techniques are
not new rules but new **edges** in the access graph:

1. Name the edge kind and its semantics in DESIGN.md §7.2, with the
   documentation that makes it an edge.
2. Build it in `internal/access` from the evaluator's decisions
   (`internal/eval`, three-valued): an UNKNOWN decision gives an edge with
   status unknown, never no edge.
3. Give every way to break it a fix in `access.Fix` (narrow, revoke,
   resolve, detach) with the cost of SCORING.md §4.1, and a guard when the
   principal can rewrite the policy the fix relies on (§4.1, "guards").
4. Add a scenario under `tests/fixtures/NN_name/{vulnerable,fixed}` with
   `darb.yaml`, its expected findings derived by hand, and the read audit of
   DESIGN.md §13.1 (a path to data must grant the read and, for KMS data, the
   decrypt).

## An input (collector and normalizer)

Collection and normalization are separate:

- A collector (`internal/collect/...`) implements
  `collect.Collector[T]`: it reads one source **read-only** into a raw type
  (`tfraw`, `k8sraw`, `awsraw`), bounded by `safeio.Limits`, and records
  every part it could not read in the `coverage.Recorder`. A live collector
  calls only the read APIs listed in [PERMISSIONS.md](PERMISSIONS.md); add any
  new call there, with its IAM action.
- A normalizer (`internal/normalize/...`) turns the raw type into the
  canonical model (`internal/model`, DESIGN.md §5). It never guesses: a value
  it cannot resolve is a placeholder plus a coverage gap of kind `unresolved`, which the
  evaluator treats as UNKNOWN.
- Wire the input in `internal/app` (`Inputs`, `Load`, `recordFiles` or
  `recordLive` for the "Scanned inputs" digest) and add its flag in
  `internal/cli`.
- Add golden files (`normalized.golden.json`, `task golden`) and review
  every changed line.

## A report format

A format implements `report.Reporter` (`Write(io.Writer, *schema.Report)`)
in its own package under `internal/report/`, reads only `pkg/schema`, and is
added to `app.Formats()` and `app.Write`. Requirements:

- deterministic output (no time unless `--timestamps`, sorted maps);
- every string from the input treated as untrusted: escape it for the
  format (see `htmlreport` and its hostile-name tests);
- the report's UNKNOWN status, coverage gaps and the "not a clean result"
  notes kept, never dropped for brevity;
- explanations (`Finding.Explanation`, `Report.ExecutiveSummary`) headed
  with `Explanation.Label()`.

When the JSON report gains a field, update `schemas/report.v1.schema.json`:
`TestSchemaDescribesTheGoTypes` fails otherwise.

## An LLM provider

A provider implements `llm.Explainer` (`Explain`, `Model`) in its own io
package under `internal/llm/` (the Claude provider, `internal/llm/claude`,
is the model) and is added to `app.LLMProviders` and `app.NewExplainer`.
It receives only what `llm.Prepare` made of the report (redacted, and
pseudonymised with `--llm-redact-identifiers`) and must:

- treat the evidence as data in its system prompt;
- ask for the JSON shape `summary`, `attack`, `fix` and return an error on
  anything else (refusal, truncation, invalid JSON), so the template is used;
- read its key from an environment variable, never a flag, and never log
  it;
- be tested against a local fake of its API, never the real service.

`llm.Explain` validates the answer, restores the identifiers and removes
control characters; the provider does not need to.
