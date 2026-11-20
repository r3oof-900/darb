# CLAPA — Cross-Layer Cloud Attack-Path Analyzer

> **Status: pre-alpha, Phase 1 of 7 (design and skeleton).** CLAPA cannot scan
> anything yet. Every command currently exits with code 2 and says so.

CLAPA models identity and permission flow across **Kubernetes and AWS as one
graph**, finds paths from attacker entry points (exposed or compromised pods) to
crown-jewel data (KMS keys, S3 buckets, secrets), explains every hop with
`file:line` or ARN evidence, and proposes the **minimal verified fix**.

Principles: no number without evidence; anything that cannot be evaluated is
reported as **UNKNOWN**, never as safe; scanning never modifies your files.

## Documents

- [docs/DESIGN.md](docs/DESIGN.md) — architecture, evaluation semantics, decisions and flagged ambiguities
- [docs/SCORING.md](docs/SCORING.md) — risk formula and remediation cut costs
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — threat model of the tool itself
- [SECURITY.md](SECURITY.md) — vulnerability disclosure

## Development

Requires Go 1.26 or newer and [Task](https://taskfile.dev).

```sh
task tools    # install pinned golangci-lint, task, lefthook, govulncheck, gitleaks
lefthook install
task ci       # vet, lint, race tests, govulncheck, fixture check
```

`-race` needs cgo and a C toolchain. On a machine without one, `task test:norace`
runs the tests without it; CI always runs with `-race`.

The package dependency rules live in `internal/archtest/layers.go`. After
changing them run `task gen`, which regenerates the depguard rules in
`.golangci.yml` and the table in `docs/DESIGN.md`.

The scenario 13 fixture uses a real Terraform plan. Regenerating it needs
Terraform (not needed by CI or the tests) and no AWS account; details in
[tests/fixtures/README.md](tests/fixtures/README.md#regenerating-the-scenario-13-plan):

```powershell
./scripts/generate-fixture-plan.ps1 -Variant vulnerable
./scripts/generate-fixture-plan.ps1 -Variant fixed
```

## License

Apache-2.0. See [LICENSE](LICENSE).
