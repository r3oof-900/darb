# Comparison with the previous tool (DESIGN.md §12.2, item 2)

Run on 2026-11-21. The previous tool (`github.com/r3oof-900/AI-CSPM-Platform_Main`,
commit `bdbeb42`, 2026-11-19) was cloned into a temporary directory outside this
repository, with its Python dependencies in a virtual environment there; nothing of
it was copied into CLAPA. Each of its four samples was copied twice, one copy per
tool, and scanned:

- previous tool: `python ai_cspm.py --target <copy> --offline --format json`
  (its deterministic engine, no LLM);
- CLAPA, pass 1: `clapa scan --root <copy> --terraform . --k8s .` with no
  `clapa.yaml`;
- CLAPA, pass 2: Terraform and manifests in their own directories, and a
  `clapa.yaml` made only from values the sample states — its variable defaults
  (account, region, EKS OIDC ID) — with the bucket the sample calls the vault
  declared as a crown jewel (the samples tag only their KMS keys).

## What the samples contain

No sample grants any S3 read (`s3:GetObject`, a bucket policy, an access point):
the roles have `kms:Decrypt` (on `"*"` in two samples, scoped and bound by the
encryption context in the two baselines) and nothing else on the buckets. The
`vulnerable_baseline` already carries the fixes the previous tool generated
(comments "REMEDIATED BY AI-CSPM"), so it and `remediated_baseline` are nearly the
same.

## Results

| Sample | Previous tool | CLAPA (pass 2) |
|---|---|---|
| `fraud_detection_ai_engine` | **attack path** AP-001 CRITICAL (workload → role → CMK); SEC-IAM-001 CRITICAL `kms:Decrypt` on `*`; SEC-IAM-002 HIGH overbroad OIDC trust (`fraud-analytics:*`); SEC-K8S-001 HIGH RBAC secrets get/list; SEC-S3-001 HIGH no Block Public Access; 10 more (logging, lifecycle, boundary, ViaService, root principal, automount, network policy, cross-layer summaries) | **no path**; `CLAPA-POST-008` high (`kms:Decrypt` on every resource, reachable from the workload); `CLAPA-POST-001` high (trust allows `system:serviceaccount:fraud-analytics:clapa-probe`) — **after the fix below**; `CLAPA-POST-004` medium; `CLAPA-POST-007` low; Block Public Access: a coverage gap |
| `healthcare_telemetry_baseline` | **attack path** AP-001 CRITICAL; SEC-IAM-001 CRITICAL; SEC-IAM-002 HIGH; SEC-S3-001 HIGH; 9 more | **no path**; `CLAPA-POST-008` high; `CLAPA-POST-007` low; Block Public Access gap |
| `vulnerable_baseline` | no attack path; SEC-K8S-001 HIGH; SEC-S3-001 HIGH; 8 more (medium/low) | no path; `CLAPA-POST-004` medium; `CLAPA-POST-007` low; Block Public Access gap (exit 3) |
| `remediated_baseline` | identical to `vulnerable_baseline` | identical to `vulnerable_baseline` |

Pass 1 (no `clapa.yaml`) gives the same findings with every ARN's account
unresolved (the samples set the account only as a variable default, and CLAPA takes
the account from `clapa.yaml` or the provider), so roles and buckets carry coverage
gaps and the scans exit 3; in `remediated_baseline` the policy JSON file in the same
directory is also read as a manifest and reported as a parse error.

## The differences, explained

1. **The "exfiltration" attack paths (fraud, healthcare).** The previous tool ends
   its path at the KMS key: decrypt capability is reported as exfiltration. Reading
   an SSE-KMS object needs both `s3:GetObject` (or another read of the bucket) and
   `kms:Decrypt`; no sample grants the read, so the data is not reachable, and CLAPA
   reports no path. The broad decrypt itself is reported by both: SEC-IAM-001
   (CRITICAL) and `CLAPA-POST-008` (high, with `reachable_from`). CLAPA treats a key
   as a means to data, not a target (DESIGN.md §8.1, decision 2).
2. **Namespace-scoped wildcard trust (fraud) — a CLAPA bug, fixed.** The trust allows
   `system:serviceaccount:fraud-analytics:*`. `CLAPA-POST-001` probed only a service
   account in a namespace of its own, so a wildcard scoped to one namespace never
   matched. Rule 1.0.1 (catalog 1.2.1) also probes a service account that is not in
   the input in every namespace of the cluster; `TestTrustWildcardInOneNamespace`.
3. **Trust without `:aud` (healthcare).** SEC-IAM-002 also fires on healthcare, whose
   trust pins `:sub` exactly and has no `:aud` condition. CLAPA does not report it:
   the subject is exact, and STS accepts only audiences in the OIDC provider's client
   ID list. EKS recommends the `:aud` condition; it is a hygiene recommendation, not
   a path.
4. **Block Public Access (all).** SEC-S3-001 reports the missing
   `aws_s3_bucket_public_access_block` as HIGH. CLAPA reports it as a coverage gap:
   an existing bucket's setting cannot be known from the configuration, and a gap is
   not a finding (§4.7); a plan that creates the bucket gives the documented default.
5. **RBAC `get`/`list` on secrets (fraud, baselines).** SEC-K8S-001 HIGH. CLAPA does
   not model Kubernetes Secrets as targets yet (§12.2 item 5, Phase 6); it reports the
   token automount for an account with RBAC permissions (`CLAPA-POST-004`).
6. **Hygiene the previous tool reports and CLAPA does not**: S3 access logging and
   lifecycle, missing permissions boundary, key policy without `kms:ViaService`, the
   account-root statement of the default key policy (which AWS documents as the
   normal delegation to IAM). These are not attack-path facts; CLAPA's scope is paths
   and the posture rules of §8.1.
7. **Network policy.** Both report the missing default-deny; the previous tool also
   for the `default` namespace, which has no workload in the samples (CLAPA reports
   namespaces with workloads only).

## Outcome

One CLAPA defect found and fixed (difference 2). The other differences are CLAPA's
documented semantics (paths need the data read; gaps are not findings; keys are
means) or scope (hygiene rules; Kubernetes Secrets in Phase 6).
