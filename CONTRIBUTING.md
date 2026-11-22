# Contributing

Thank you for helping. Security issues go through
[SECURITY.md](SECURITY.md), never a public issue.

## Running the tests

Go 1.26 or newer and [Task](https://taskfile.dev):

```sh
task tools        # pinned golangci-lint, govulncheck, gitleaks, lefthook
lefthook install  # the pre-commit hooks: secrets scan and lint
task ci           # vet, lint, race tests, govulncheck, fixture check
```

`-race` needs cgo; without a C toolchain, `task test:norace`. CI runs every
check on Linux, macOS and Windows. The tests never call a real cloud API:
fakes, LocalStack and kind only.

## Expected results are written by hand, before the engine

Every scenario under `tests/fixtures/` has an `expected.json` derived **by
hand** in `tests/fixtures/expected_source.py`, with the score arithmetic in
comments, from [docs/DESIGN.md](docs/DESIGN.md) and
[docs/SCORING.md](docs/SCORING.md), **before** the engine is run on it.

- Never generate an expected result from the tool's output, and never change
  one to match the tool. When they differ, record the difference in
  `internal/app/testdata/open_mismatches.txt` and investigate which is wrong.
- Fixtures are immutable: tests copy them first, and CI fails if a test changes
  one.
- Normalization goldens (`normalized*.golden.json`) are regenerated with
  `task golden`; review every changed line.

[docs/EXTENDING.md](docs/EXTENDING.md) explains how to add a rule, an edge, an
input, a format or an LLM provider within these rules.

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/):
  `feat(scope): …`, `fix(scope): …`, `docs: …`, `test(fixtures): …`,
  `build(release): …`.
- Every pull request needs green CI. Hooks are not skipped.
- A new dependency must be at least two weeks old (`go run ./tools/depage`),
  and every GitHub Action is pinned to a commit SHA.
- Every claim about AWS or Kubernetes behaviour cites its documentation.
- UNKNOWN is never counted as secure.
