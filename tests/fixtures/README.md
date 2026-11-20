# Golden scenarios

The 17 scenarios of docs/DESIGN.md section 13, each with a `vulnerable` and a
`fixed` variant. Fixtures are **immutable**: tests copy each variant to a
temporary directory before reading it (`internal/app/golden_test.go`), and CI
fails if `git diff --exit-code -- tests/fixtures` is not clean after the tests.

## Layout of a variant

| Path | Meaning |
|---|---|
| `clapa.yaml` | configuration (account, region, cluster `prod` and its IRSA issuer, intended access) |
| `terraform/` | Terraform scanned statically (HCL) |
| `plan.json` | Terraform plan JSON; when present, the variant is scanned from the plan, and `terraform/` separately in static mode |
| `k8s/` | Kubernetes manifests of cluster `prod` |
| `snapshot/` | an offline AWS snapshot (`clapa-snapshot/v1`) |
| `normalized.golden.json` | the normalized inventory, coverage gaps and entry points (Phase 3) |
| `normalized.static.golden.json` | the same for the static scan, when a plan is present |
| `expected.json` | findings by rule ID and fingerprint (added in Phase 4, with the rules) |

Regenerate goldens with `task golden` and review every changed line: a golden
diff is a behaviour change.

## Scenarios

| # | Directory | Tests | Vulnerable | Fixed |
|---|---|---|---|---|
| 1 | `01_classic` | IRSA → role → `kms:Decrypt` on `*` + `s3:GetObject` → CMK → PII bucket | path | reads only the receipts bucket, decrypt scoped by encryption context |
| 2 | `02_ec_scoped_to_legit_bucket` | read + decrypt on bucket A, `kms:EncryptionContext:aws:s3:arn` = A; A is `intended_access`; PII bucket B has its own key | no path to B; access to A "intended access verified" | additionally a Deny bucket policy on B |
| 3 | `03_ec_other_bucket` | `s3:GetObject` on PII bucket B, decrypt on B's key only with another bucket's encryption context | no path to B | no read on B at all |
| 4 | `04_wildcard_sub` | trust `StringLike :sub = system:serviceaccount:*:*` | any SA → role → PII | `:sub` pinned |
| 5 | `05_aud_only` | trust with `:aud` only | any SA → role → PII | `:sub` pinned |
| 6 | `06_role_chain_cross_account` | `sts:AssumeRole` on `*` → `AdministratorAccess` role in account 444455556666 trusting 111122223333 root | cross-account path | AssumeRole scoped to one role |
| 7 | `07_passrole_lambda` | `iam:PassRole` on `*` + `lambda:CreateFunction` + `lambda:InvokeFunction` → role reading PII | escalation path | PassRole scoped and conditioned, no InvokeFunction |
| 8 | `08_rbac_create_pods` | SA `ci` may `create pods` in `payments`, where SA `api` has an IRSA role reading PII | escalation path | `get/list/watch` only |
| 9 | `09_hostnetwork_imds` | `hostNetwork` DaemonSet, IMDSv1 (`http_tokens = optional`, hop limit 2) → node role → `s3:GetObject` on `*` → SSE-S3 PII bucket | path with precondition | IMDSv2 required, hop limit 1, no hostNetwork |
| 10 | `10_kms_principal_org_id` | key policy grants `kms:Decrypt` to `{"AWS": "*"}` with `aws:PrincipalOrgID` | UNKNOWN unless the org ID is configured | key policy names the role |
| 11 | `11_boundary_deny` | scenario 1 + a permissions boundary with an explicit Deny on the PII objects | no path (boundary deny) | boundary that allows only queues and logs |
| 12 | `12_public_bucket` | bucket policy `Principal "*"`, Block Public Access off, SSE-S3 | public read | Block Public Access on, policy names one role |
| 13 | `13_module_for_each` | module + `for_each` → 3 IRSA roles reading PII (`toset(...)` + `aws_iam_role.r[each.value]`; bucket SSE-S3 stated explicitly). `plan.json` is real `terraform show -json` output (see below), scanned with `terraform/` as its configuration | plan: 3 roles resolved; static: unresolved, reported | roles read a non-PII bucket |
| 14 | `14_same_names_two_accounts` | role `app` and bucket `data-<account>` in two accounts (snapshot) | two distinct nodes, no ID collision | account 444455556666's role can only list |
| 15 | `15_empty_input` | nothing to scan | `collected: 0` → exit 3, never "0 findings" | one namespace manifest |
| 16 | `16_malformed_inputs` | malformed YAML and HCL next to a valid copy of scenario 1 | both reported with file:line; the rest is loaded | valid files only |
| 17 | `17_pod_identity_classic` | scenario 1 through EKS Pod Identity: association payments/api, trust `pods.eks.amazonaws.com` for `sts:AssumeRole` + `sts:TagSession` pinned by session tags, agent add-on | path (as scenario 1) | as scenario 1 fixed |

For the "no path" scenarios (2, 3, 11) the vulnerable variant is the near-miss
configuration that must *not* produce a path; the fixed variant is a hardened
version that must not either.

## Regenerating the scenario 13 plan

`13_module_for_each/<variant>/plan.json` is real Terraform output, made without
an AWS account:

```powershell
./scripts/generate-fixture-plan.ps1 -Variant vulnerable
./scripts/generate-fixture-plan.ps1 -Variant fixed
```

The plan collector's real test plans are regenerated the same way, e.g.
`./scripts/generate-fixture-plan.ps1 -Source internal/collect/terraform/plan/testdata/for_each_map/terraform -Out internal/collect/terraform/plan/testdata/for_each_map/plan.json`.

The script copies `terraform/` to a temporary directory (the fixture is not
touched), adds a `mock_override.tf` with fake credentials,
`skip_credentials_validation`, `skip_requesting_account_id`,
`skip_metadata_api_check`, `skip_region_validation` and
`allowed_account_ids = null` (the provider cannot check the allowed account
without looking it up; `clapa.yaml` sets the account), then runs
`terraform init`, `terraform plan -refresh=false -out=plan.tfplan` and
`terraform show -json plan.tfplan`. Nothing is applied and no AWS API is
called. Committed files were made with Terraform 1.17.1 and `hashicorp/aws`
6.73.0. Review the diff and the goldens (`task golden`) before committing.
