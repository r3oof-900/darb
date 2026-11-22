# darb — Threat model of the tool itself

Scope: the `darb` binary, its inputs and outputs, its CI/release pipeline. Method:
assets → trust boundaries → threats (STRIDE) → controls. Each control names where
it is enforced; "Phase N" means the control lands in that phase.

## 1. Assets

| Asset | Why it matters |
|---|---|
| Cloud credentials (AWS profile / role sessions), kube credentials and EKS tokens | read access to the whole estate |
| Scan results (reports, graph exports, baselines) | **a ranked map of how to breach the environment**; as sensitive as credentials |
| User inputs (Terraform, manifests, snapshots) | may embed secrets; must never be modified by a scan |
| LLM API key and LLM-bound evidence | data leaves the machine only via this path |
| Release artefacts (binaries, image, Homebrew formula) | supply-chain target |

## 2. Trust boundaries

1. **Input files** — untrusted (may come from a PR by an outsider in CI).
2. **Cloud / Kubernetes APIs** — authenticated, but returned data (names, tags,
   annotations, policy text) is attacker-influenceable.
3. **Output sinks** — terminal, files, CI annotations (SARIF), browsers (HTML).
4. **LLM provider** — third party; opt-in only.
5. **Build/CI pipeline** — third-party actions and Go modules.

## 3. Threats and controls

### Spoofing
| Threat | Control |
|---|---|
| MITM against cloud/K8s APIs | TLS verification on; `--insecure` loud warning + recorded in report (Phase 6) |
| PATH hijack of `terraform` when converting a plan file | `exec.LookPath` (refuses cwd-relative results since Go 1.19) or explicit `--terraform-bin`; argument slice, no shell (Phase 3) |

### Tampering
| Threat | Control |
|---|---|
| Scan modifies user inputs (the old tool's auto-fix overwrote its own vulnerable sample) | scan is read-only; remediation writes to a separate dir or prints a diff; `--write` refuses a dirty git tree without `--force`; fixtures copied to tmp in tests; CI `git diff --exit-code -- tests/fixtures` |
| Output path traversal (`--output ../../etc/x`, archive-style names) | `internal/safeio` cleans and confines output paths; refuses to overwrite inputs (Phase 3) |
| Symlink in an input tree pointing outside the scan root | symlinks not followed outside the root (Phase 3) |
| Malicious dependency / action | `go.sum` committed, `GOFLAGS=-mod=readonly`, Dependabot, `govulncheck`, actions pinned by commit SHA (Phase 1) |
| Release tampering | `.goreleaser.yaml` + `release.yml` (Phase 7): reproducible builds (`-trimpath`, no build ID, commit time as file time; CI builds every change twice and requires identical archives), an SPDX SBOM per archive (syft), `checksums.txt` signed keylessly with cosign (a Sigstore bundle bound to the release workflow's identity), and SLSA build provenance (GitHub artifact attestations). Releases are drafts until a maintainer publishes them. Verification commands are in the README |

### Repudiation
| Threat | Control |
|---|---|
| Disputed result ("the tool said it was fine") | reports carry tool version, rule-catalog version, input digests, coverage, assumptions, insecure flags; deterministic output allows re-verification |
| Silent suppression | suppressions require reason, owner, expiry; expired ones re-fire and are listed |

### Information disclosure
| Threat | Control |
|---|---|
| Secrets from inputs reaching logs | everything the CLI writes to standard error passes through the redactor (`internal/redact`, 48 value formats plus secret-named keys); a redacting `slog` handler exists for any future structured log; tokens never logged. *Correction (Phase 7):* earlier versions of this table said the handler existed from Phase 2; `internal/redact` was a stub until Phase 7 and the CLI wrote errors unredacted. Both are now implemented and tested (`TestStderrIsRedacted`, `TestHandler`) |
| Reports leaking via world-readable files | output files created with mode `0600` (Phase 4) |
| Evidence sent to an LLM | off by default (`--llm anthropic`); the key is read from `ANTHROPIC_API_KEY` only (never a flag, never printed or reported); structured fields of the report only (`llm.Evidence`: rule, severity, score, status, entry, jewel, path, undecided, cheapest fix, defaults), never a file of the input; every string through the secret redactor (48 formats, false-positive corpus); `--llm-redact-identifiers` replaces account IDs, ARNs and names by tokens restored locally, one mapping per report; misconfigurations are never sent, only path findings and the summary. Residual risk: without `--llm-redact-identifiers`, resource names and account IDs reach the provider |
| Unexpected network egress | the tool talks only to the cloud APIs being read and the explicitly enabled LLM provider; no telemetry, no update checks |
| Supply chain of the LLM provider | no SDK: `internal/llm/claude` speaks the Messages API over `net/http` (standard library only). The Anthropic SDK and its 15 indirect modules (OpenTelemetry, `tidwall/*`, `invopop/jsonschema`, `standard-webhooks`, a release-candidate `yaml/v4`) were removed in Phase 7, so nothing extra is linked into the binary for `--llm` |

### Denial of service
| Threat | Control |
|---|---|
| Huge files, YAML alias bombs ("billion laughs"), deep nesting | per-file size cap, nesting-depth cap, alias-expansion limits, regular files only (Phase 3) |
| Path explosion in large graphs | bounded depth, per-pair path cap, reachability + min-cut instead of exhaustive enumeration, context timeouts (Phase 4) |
| API throttling storms | adaptive retry, bounded concurrency per service (Phase 6) |

### Elevation of privilege / injection
| Threat | Control |
|---|---|
| XSS in the HTML report via resource names/tags | `html/template` auto-escaping, data as escaped JSON, strict CSP with hashed inline assets, test with `<script>` names (Phase 7) |
| Terminal escape-sequence injection via names in console output | control characters stripped from every untrusted string before printing (Phase 4) |
| Markdown/SARIF injection into CI annotations | untrusted strings escaped per format (Phase 4) |
| Prompt injection via resource names into the LLM | LLM output is explanation only: it is stored beside the verdict, score and fix and never read back by the engine; the system prompt states that evidence is data; the answer must match a JSON schema, each part ≤ 4000 characters, control characters removed, HTML-escaped, and labelled "AI-generated explanation" in every format; any failure (timeout, refusal, cap, invalid JSON) falls back to template text with a note. Residual risk: an injected name can make the *explanation* wrong or misleading; the label and the engine's own fields beside it are the mitigation |
| Code execution through templates | no `text/template` for HTML; Terraform function whitelist only; no `unsafe`; no `os/exec` except the plan conversion (enforced by `internal/archtest`) |
| Overly broad live-scan permissions | documented minimal read-only policy (`docs/PERMISSIONS.md`, Phase 6) |

## 4. Residual risks (accepted)

- A user who scans with admin credentials gives the process admin rights; darb
  only issues read calls, but cannot prevent a compromised dependency from using them.
  Mitigated by the supply-chain controls above; recommended: run with
  `SecurityAudit` + `ViewOnlyAccess`.
- Reports are sensitive by nature; darb cannot control where users store them.
  The README states this explicitly.
- False negatives from unmodelled AWS features (KMS grants, S3 ACLs, VPC endpoint
  policies) are reported as coverage gaps, never hidden.
