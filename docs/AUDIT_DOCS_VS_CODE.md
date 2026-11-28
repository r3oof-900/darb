# Audit: documentation against code

Done on 2026-11-22, at the end of Phase 7, on branch `phase7-llm`. Every claim
below was checked against the code or the binary, not against other documents.
"Fixed" means changed in this branch, with a test where one applies; "corrected"
means the document was wrong and now says what the code does; "open" is left
for review. Findings 4 and 6 were fixed after the audit, in the same pull
request.

## Method

- **Flags and commands.** The flag list of every command was read from the
  built binary (`darb <command> -h`) and compared, both ways, with every
  `--flag` named in README, CONTRIBUTING and `docs/*.md`.
- **Constants and tables.** Fix costs (SCORING.md §4.1) against
  `scoring.FixCost`; rule IDs, versions and base severities (DESIGN.md §8.1)
  against `darb rules list` and `internal/rules/posture`; exit codes and their
  precedence (§11) against `internal/cli/exitcode.go`; the redaction format
  count (§10) against `internal/redact`; `darb.yaml` keys against
  `internal/config`.
- **Behaviour.** The LLM client, doctor, graph, network egress and the live
  collectors' calls were read in code; claims already pinned by a test (layer
  table, permissions, schemas, SARIF, goldens) were confirmed by running it.

## Findings

| # | Document said | Code did | Outcome |
|---|---|---|---|
| 1 | Each command takes the flags its usage lists | `remediate`, `explain`, `graph` and `doctor` parsed shared flags they then ignored (`remediate --output`, `explain --baseline`, `graph --ignore`, `doctor --aws-assume-role`, …), so a user could believe a setting applied | **fixed**: such a flag is a usage error naming it (`TestUnusedFlagsAreRefused`) |
| 2 | DESIGN.md §4.1, THREAT_MODEL: the terraform binary is found on PATH "or an explicit `--terraform-bin`" | the plan reader had the option; no CLI flag reached it | **fixed**: `--terraform-bin` on every command that reads inputs (`TestTerraformBinFlag`) |
| 3 | a recovered panic: "re-run with `--debug` for a stack trace" | there is no `--debug` | **fixed**: the message says it is a bug to report |
| 4 | DESIGN.md §15 (logging): `slog`, `--log-format json`, `--debug` | the redacting `slog` handler existed and standard error was redacted; darb wrote no structured log; neither flag existed | **fixed** after the audit: `--log-format text\|json` and `--debug` (global), redacted records, stack traces with `--debug` (`TestJSONLogsAreRedacted`, `TestCLIJSONLogs`, `TestCrash`) |
| 5 | DESIGN.md §5: entry points "(`--assume-compromised`, default on)" | a `darb.yaml` setting, `threat_model.assume_compromised`; no flag | **corrected** |
| 6 | `internal/report/junit` and `internal/report/markdown`: "Implemented in Phase 7" | both packages were empty; no format wrote JUnit or Markdown | **fixed** after the audit: `--format markdown` (PR comment, size-bounded) and `--format junit` (validated against the JUnit 10 XSD in CI) |
| 7 | `darb.yaml` keys | `crown_jewels` (`tag_keys`, `tag_values`, `explicit`), `threat_model.assume_compromised` and `clusters[].oidc_issuer` were documented nowhere; `--config` was in no document | **fixed**: [docs/CONFIG.md](CONFIG.md), every key with its checks; its example is parsed by darb |
| 8 | DESIGN.md §11: `doctor` probes `iam:SimulatePrincipalPolicy` "when allowed" | not called: it is outside the read-only policy of docs/PERMISSIONS.md | **open** (recorded in §11) |
| 9 | integration tests cover every live call | LocalStack ran without `s3control`, so the account Block Public Access call always failed (correctly recorded as unknown, never read back) | **fixed**: service enabled; the test sets the account setting and requires it read back |
| 10 | README, FAQ, PERMISSIONS: KMS grants "can only make darb report a path that is blocked, never hide one"; DESIGN §6 and THREAT_MODEL: their absence "reported as a coverage gap" | a grant can give `kms:Decrypt` to a principal the key policy does not name, so missing grants **can hide a real path**; and nothing was recorded: no gap, no note, so a scan with keys could look complete | **fixed** (found after this audit, during the release review): every report with KMS keys carries a `not-modelled` note naming them; documents corrected; grants are now collected and evaluated (after v0.1.0-rc.1, scenario 25), the note remains for runtime grants in Terraform and grants not listed |
| 11 | DESIGN §6: "S3 ACLs are not modelled; reported as a gap"; THREAT_MODEL: reported as gaps | nothing was recorded; an ACL can grant read access, so this too **can hide a real path** | **fixed** (same review): a `not-modelled` note naming the buckets; documents corrected; Object Ownership is now collected (after v0.1.0-rc.1, scenario 26): a bucket ACL only lists objects, and an ACL-enabled bucket is a gap for its object ACLs |
| 12 | FAQ, PERMISSIONS: SCPs and RCPs "listed in every report as `not-modelled`"; FAQ's list also named account-level Block Public Access, collected since this phase | no report mentioned SCPs or RCPs | **fixed**: a `not-modelled` note on every scan with AWS data; FAQ's list corrected |

Earlier in Phase 7, the same kind of check found and fixed: THREAT_MODEL's
claim that a redacting log handler existed since Phase 2 (it was a stub); SARIF
without the code flows and `%SRCROOT%` locations §11 promised; the RAM note
"listed in every report" (it now names the shareable parameters, and only when
there are some); `internal/report/sarif` not validated against the official
schema (now validated).

Findings 10 to 12 were **missed by this audit**: it compared the documents
with one another and with code paths, but did not check, for each stated limit,
that a report actually carries it. That check is now a test: DESIGN.md §12.3
lists every limit with the note or gap that states it and a scenario, and
`TestStatedLimits` requires each one in that scenario's report, and every note
the code writes in the table.

## Verified consistent

| Claim | Where | Checked against |
|---|---|---|
| Every `--flag` the documents name for darb exists (the others are cosign, sha256sum, git or `tools/refresh-managed-policies` flags) | README, DESIGN, FAQ, PERMISSIONS, CONFIG | `darb <command> -h` for all six commands |
| Commands: scan, explain, graph, remediate, rules, collect-snapshot, doctor, version | DESIGN.md §11, README | `internal/cli/run.go` |
| Exit codes 0–4 and precedence 4 > 2 > 1 > 3 > 0 | DESIGN.md §11, README, FAQ | `internal/cli/exitcode.go` |
| Fix costs: identity 1/3, resource 2/4, trust 5/7, IAM escalation 2/4, node 3/5, workload 5 (token, hostNetwork, mount), RBAC 5, mapping 8, exposure 20, `RUNS_AS` 100 | SCORING.md §4.1 | `scoring.FixCost`, `workloadCost` |
| 11 rules, their versions and base severities | DESIGN.md §8.1 | `darb rules list`, `internal/rules/posture` |
| 48 secret formats (DESIGN.md §10 requires ≥ 40) | DESIGN.md §10, THREAT_MODEL | `internal/redact` (`TestEveryFormatIsRedacted`) |
| LLM: key only from `ANTHROPIC_API_KEY`, model `claude-opus-5-5`, 2 minutes, 2 retries, 4000 tokens, `Retry-After`, 1 MiB bound, fallbacks | DESIGN.md §10, README, FAQ | `internal/llm/claude`, its tests against a local fake |
| Outbound network: only the cloud APIs read and the enabled LLM provider | THREAT_MODEL | `net/http` users: `internal/llm/claude`, the EKS token in `internal/collect/k8s/live`; AWS and Kubernetes SDKs in the collectors; `tools/depage` is a development tool, not in the binary |
| Live collection read-only; PERMISSIONS.md lists exactly the calls | PERMISSIONS.md | `TestClientInterfacesAreReadOnly`, `TestPermissionsDocument`, `TestK8sPermissionsDocument` |
| Layer table | DESIGN.md §3.2 | generated by `tools/archgen`; `internal/archtest` |
| Report JSON matches its schema; SARIF matches the OASIS schema | DESIGN.md §11 | `TestEveryReportMatchesTheSchema`, `TestEverySARIFReportMatchesTheOfficialSchema` |
| README's example output is the tool's | README | the scan of scenario 01, line by line |
| `intended_access` is verified for `s3:GetObject` on buckets only | CONFIG.md | `verifyIntended` |

## Open for review

- `doctor` and `iam:SimulatePrincipalPolicy` — #8.
- Not part of this audit's fixes, recorded in DESIGN.md §12.1 and §15.1: the
  managed-policy snapshot (3 policies then; refreshed from IAM on 2026-11-23,
  1622), RAM shares (named, not collected).
