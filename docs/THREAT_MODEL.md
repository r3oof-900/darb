# CLAPA — Threat model of the tool itself

Scope: the `clapa` binary, its inputs and outputs, its CI/release pipeline. Method:
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
| Release tampering | goreleaser reproducible builds, SBOM (syft), cosign signatures, SLSA provenance (Phase 7) |

### Repudiation
| Threat | Control |
|---|---|
| Disputed result ("the tool said it was fine") | reports carry tool version, rule-catalog version, input digests, coverage, assumptions, insecure flags; deterministic output allows re-verification |
| Silent suppression | suppressions require reason, owner, expiry; expired ones re-fire and are listed |

### Information disclosure
| Threat | Control |
|---|---|
| Secrets from inputs reaching logs | redacting `slog` handler (key and value patterns, `internal/redact`); tokens never logged (Phase 2–6) |
| Reports leaking via world-readable files | output files created with mode `0600` (Phase 4) |
| Evidence sent to an LLM | off by default; structured evidence only, never raw files; secret redactor with ≥ 40 formats and a false-positive corpus; optional pseudonymisation of identifiers (Phase 7) |
| Unexpected network egress | the tool talks only to the cloud APIs being read and the explicitly enabled LLM provider; no telemetry, no update checks |

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
| Prompt injection via resource names into the LLM | LLM output is explanation only: it cannot change verdicts, scores or fixes; output is escaped like untrusted input (Phase 7) |
| Code execution through templates | no `text/template` for HTML; Terraform function whitelist only; no `unsafe`; no `os/exec` except the plan conversion (enforced by `internal/archtest`) |
| Overly broad live-scan permissions | documented minimal read-only policy (`docs/PERMISSIONS.md`, Phase 6) |

## 4. Residual risks (accepted)

- A user who scans with admin credentials gives the process admin rights; CLAPA
  only issues read calls, but cannot prevent a compromised dependency from using them.
  Mitigated by the supply-chain controls above; recommended: run with
  `SecurityAudit` + `ViewOnlyAccess`.
- Reports are sensitive by nature; CLAPA cannot control where users store them.
  The README states this explicitly.
- False negatives from unmodelled AWS features (KMS grants, S3 ACLs, VPC endpoint
  policies) are reported as coverage gaps, never hidden.
