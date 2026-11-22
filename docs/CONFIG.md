# darb.yaml

`darb.yaml` in the scan root (or `--config FILE`) says what the input does not:
where Terraform resources live, which clusters exist, what counts as a crown
jewel, and what must not be cut. Every key is optional except `version`.
Unknown keys are errors, so a typo cannot silently turn a setting off
(`internal/config`). A value that contains darb's reserved placeholder text
(`${darb:unresolved:`) is refused.

```yaml
version: 1

terraform:                     # for resources whose provider does not say
  account: "111122223333"      # 12-digit account ID
  region: us-east-1
  partition: aws               # default aws

clusters:                      # Kubernetes clusters of --k8s and live scans
  - name: prod                 # required; unique per account and region
    account: "111122223333"
    region: us-east-1
    oidc_issuer: https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E

crown_jewels:                  # what counts as sensitive data
  tag_keys: [DataClass]        # default [DataClass]
  tag_values: [pii, pci, phi, secret]   # default; the value is the classification
  explicit:
    - {arn: "arn:aws:s3:::acme-customer-pii", classification: pii}
  unclassified: include        # default; ignore: untagged data stores are no jewels

threat_model:
  assume_compromised: true     # default true: every workload is an entry point

assume:                        # values for condition keys the input cannot know
  "aws:PrincipalOrgID": ["o-a1b2c3d4e5"]

intended_access:               # access no fix may remove (verified, reported)
  - {principal: "k8s:prod/payments/Deployment/api", action: "s3:GetObject", resource: "arn:aws:s3:::acme-receipts/*"}

remediation:
  cut_costs: {ASSUMES: 7}      # per edge kind, integers >= 1 (docs/SCORING.md §4)
  uncuttable_edges:            # edges no fix may cut
    - {kind: ASSUMES, from: "k8s:...", to: "arn:aws:iam::111122223333:role/break-glass", reason: "break-glass role"}

coverage:
  tolerance: {unresolved: 2}   # gaps of a kind tolerated before exit code 3; default 0 each
```

| Key | Meaning | Checked |
|---|---|---|
| `version` | must be `1` | yes |
| `terraform.account`, `.region`, `.partition` | the account, region and partition of Terraform resources whose provider names none; an unknown account is an unresolved placeholder and a gap, never "" | account must be 12 digits |
| `clusters[]` | `name` (as `--k8s DIR=NAME` and findings use it), `account` and `region` (the cluster's identity becomes its EKS ARN), `oidc_issuer` (IRSA: the issuer roles must trust) | name required and unique; account 12 digits; issuer `https://` |
| `crown_jewels.tag_keys`, `.tag_values` | a resource tagged with one of the keys and one of the values is a crown jewel, classified by the value (docs/SCORING.md §1.2) | — |
| `crown_jewels.explicit[]` | resources marked by ARN with a classification | — |
| `crown_jewels.unclassified` | `include` (default): a data store (S3 bucket, Secrets Manager secret, SecureString parameter, Kubernetes Secret) that nothing above classifies is a crown jewel of classification `unclassified` (value 400, not counted in blast radius, no posture rules), named in a coverage note; `ignore`: it is no jewel, and the note says it was not scanned (DESIGN.md §5) | `include` or `ignore` |
| `threat_model.assume_compromised` | with `true`, every workload is an entry point (exposure 400); with `false`, only exposed ones (DESIGN.md §5) | — |
| `assume` | condition-key values for the evaluator (for example `aws:PrincipalOrgID`); an unknown key otherwise makes a decision UNKNOWN (DESIGN.md §6.2) | — |
| `intended_access[]` | `principal` (a workload, `k8s:{cluster}/{namespace}/{kind}/{name}`), `action`, `resource`: access the remediation must keep and the report verifies (`verified`, `unconfirmed`, `not-satisfied`). Verified for `s3:GetObject` on a bucket of the input only; anything else is reported `not-modelled`. A pair declared for a whole bucket (`<bucket ARN>/*`) is not reported as a finding; a prefix is | all three required |
| `remediation.cut_costs` | overrides the cost of every edge of a kind (`ASSUMES`, `CAN_READ`, …) | integers ≥ 1 |
| `remediation.uncuttable_edges[]` | an edge (`kind`, `from` and `to` by canonical identity, exact match) no fix may cut | all four required |
| `coverage.tolerance` | per gap kind (`unresolved`, `unknown-after-apply`, `parse-error`, `unsupported`, `not-modelled`, `access-denied`, `throttled`, `timeout`, `api-error`), how many gaps are tolerated; a plan attribute the provider computes is never counted | integers ≥ 0 |

Suppressions are a separate file, `.darb-ignore.yaml` (or `--ignore FILE`):
each entry needs `fingerprint`, `reason`, `owner` and `expires` (docs/FAQ.md).
