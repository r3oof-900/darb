# CLAPA — Risk scoring and remediation cut costs

This is the complete, transparent formula. Every finding prints each factor below
next to its score. **This is not CVSS** and is never labelled as such; CLAPA does
not compute CVSS 4.0 vectors.

All arithmetic is **integer fixed point in per-mille** (0–1000), with floor
division after each multiplication, so scores are bit-identical on every platform
(see DESIGN.md §3.4). `a ⊗ b` below means `a * b / 1000` (integer, floor).

## 1. Path findings

```
score      = likelihood ⊗ impact                      (0–1000)
likelihood = exposure ⊗ hops ⊗ preconditions ⊗ confidence
impact     = min(1000, classification ⊗ blast_radius)
```

### 1.1 Likelihood factors

| Factor | Value (per-mille) | Source |
|---|---|---|
| **exposure** — entry point | `1000` public `LoadBalancer` / `Ingress`; `800` `NodePort`; `500` internal load balancer; `400` any workload under the "assume any pod compromised" threat model | entry-point classification (DESIGN.md §5) |
| **hops** | `1000` for 1 edge, then × `900` per extra edge: 1→1000, 2→900, 3→810, 4→729, 5→656, … | number of edges on the path |
| **preconditions** | product over the path's preconditions: `900` each if known satisfied (extra attacker effort, e.g. reaching IMDS); `500` each if UNKNOWN | edge preconditions (e.g. `NODE_ROLE`) |
| **confidence** | lowest edge confidence on the path: `high` 1000, `medium` 700, `low` 400 | edge confidence (e.g. `low` when it depends on `Unresolved` values) |

### 1.2 Impact factors

| Factor | Value (per-mille) | Source |
|---|---|---|
| **classification** — crown jewel | `secret`, `pci`, `phi` 1000; `pii` 900; `confidential` 700; default heuristic "tagged sensitive" 600; `internal` 400 | crown-jewel marking (configurable map) |
| **blast_radius** | `1000 + 100 × floor(log2(N))`, capped at `1500`, where `N` = number of distinct crown jewels reachable from the same entry point | path engine reachability |

### 1.3 Severity bands

| Severity | Score |
|---|---|
| critical | ≥ 700 |
| high | 450–699 |
| medium | 250–449 |
| low | 100–249 |
| info | < 100 |

A path whose decision anywhere is `UNKNOWN` keeps its computed score but is marked
**unconfirmed**, carries `confidence: low`, and lists the unresolved conditions;
`--fail-on` counts it (safer: an unknown is not a pass).

### 1.4 Worked example (fixture 01, classic)

Public `LoadBalancer` → Deployment `RUNS_AS` SA → `ASSUMES` role →
`CAN_READ_PLAINTEXT` PII bucket (3 edges), all `high`, no preconditions, one jewel.

```
likelihood = 1000 ⊗ 810 ⊗ 1000 ⊗ 1000 = 810
impact     = min(1000, 900 ⊗ 1000)   = 900
score      = 810 ⊗ 900               = 729  → critical
```

Same path when the workload is *not* exposed and only the "assume compromised"
model applies: likelihood `400 ⊗ 810 = 324`, score `324 ⊗ 900 = 291` → medium.

## 2. Posture findings

Single-resource rules (IMDSv1, privileged pod, automount, missing public access
block, KMS rotation off, wildcard OIDC `sub`, no default-deny NetworkPolicy) carry
a **base severity** declared in the rule's metadata with a rationale. The score is
`base ⊗ confidence`, with base `critical 850, high 600, medium 350, low 150`.

## 3. Configuration

```yaml
scoring:
  classification_weights: { pii: 900, pci: 1000 }   # overrides; per-mille
  exposure_weights: { node_port: 800 }
```

Overrides are recorded in the report next to each score.

## 4. Remediation cut costs (min-cut capacities)

The chokepoint search (DESIGN.md §7.4) is a **weighted** minimum cut. An edge's
capacity is the cost of the **cheapest change that breaks it**, not a fixed
price for its kind (decided in the third Phase 4 review): the cheapest
*disruption* wins, not the shortest path. Without weights the min-cut would
happily cut `RUNS_AS` or `ASSUMES` — i.e. break the application's own identity.

### 4.1 Sides of an edge

An edge the evaluator decides has up to two sides, and each side is a separate
fix. A side counts only if deciding the request again **without** that side's
policies no longer grants (ALLOW or UNKNOWN both count as granting); a side
whose removal changes nothing is not a fix. Edges that come from facts (a pod's
service account, a mapping, an RBAC binding) have exactly one side.

| Edge | Side | Typical fix | Cost |
|---|---|---|---|
| `CAN_READ`, `CAN_DECRYPT`, `ASSUMES` (role → role) | **identity** | narrow the principal's identity policy (`Resource` to exact ARNs, an encryption-context condition, the exact role ARN for `sts:AssumeRole`) | **1** |
| `CAN_READ` | **resource** | narrow the bucket policy (replace `"*"` with explicit principals) | **2** |
| `CAN_DECRYPT` | **resource** | narrow the key policy | **2** |
| `ASSUMES` (role → role, SA → role: IRSA / Pod Identity / PassRole) | **trust** | tighten the trust policy (principal, `:sub` / `:aud`, `sts:ExternalId`, `aws:PrincipalArn`) | **5** |
| `CAN_ESCALATE` (IAM permission: PassRole, UpdateAssumeRolePolicy, Put/Attach policy) | identity | remove the escalation permission | **2** |
| `NODE_ROLE` | node | require IMDSv2, hop limit 1 | **3** |
| `CAN_ESCALATE` via K8s token (automount) | workload | `automountServiceAccountToken: false` | **3** |
| `CAN_ESCALATE` via K8s RBAC | rbac | remove/limit the binding (`create pods`, `pods/exec`, `impersonate`, `serviceaccounts/token`) | **5** |
| `MAPS_TO` (`aws-auth` / access entry) | mapping | remove/narrow the mapping | **8** |
| `RUNS_AS` | workload | change the workload's identity | **100** |
| `PROTECTS` | — | structural fact, not a permission | **∞** |
| `EXPOSED_TO` | — | not a graph edge yet: exposure is a scoring factor of the entry (DESIGN.md, deferred to Phase 5), so "remove internet exposure" is never proposed | — |
| `CAN_READ_PLAINTEXT` (derived) | — | the cut names the cheaper of its `CAN_READ` / `CAN_DECRYPT` (`CAN_DECRYPT` on a tie) | min of the two |

The edge's capacity is its cheapest side. An edge with no side left is
**uncuttable**: no single change breaks it.

### 4.2 A principal that can grant itself the access again

A cut only counts if the principal cannot undo it. After a principal that can
give itself the access back, identity-side cuts do not count, and a resource
side it can rewrite does not count either; the cut moves before it:

- a **"role with any permission"** — a principal that can rewrite its own
  policies (DESIGN.md §7.4) — has no identity side on any of its edges;
- a principal that can **rewrite the target's resource policy** —
  `s3:PutBucketPolicy` on the bucket, `kms:PutKeyPolicy` or `kms:CreateGrant`
  on the key, `iam:UpdateAssumeRolePolicy` on the role — loses that resource
  (or trust) side; and, when it is in the resource's own account (where that
  resource policy alone grants), its identity side too: cut its identity grant
  and it writes the grant back on the resource. Across accounts its identity
  grant is still required, so that side still counts.

Scenario 6 is the reference: `analytics-admin` can rewrite its own policies, the
warehouse key's policy and the bucket policy, so nothing after it is cuttable;
the cut is `ASSUMES payments-api -> analytics-admin`, identity side, cost 1
(remove `sts:AssumeRole` on that role from `payments-api`), with the trust side
(cost 5) as the other fix.

### 4.3 What a finding reports

- `chokepoints`: the cut edges; `cut_cost`: the sum of their capacities.
- `fix`: for each cut edge, the side the cut chose (its cheapest), the policy
  to change and its cost; `other_side_fix`: the other sides that also break
  that edge, dearer.
- `alternative_fix`: for a cut `CAN_READ_PLAINTEXT`, the underlying edge of
  equal cost that was not chosen.
- `shared_fix_possible: [<resource ARN>]`: one change to that resource's policy
  can break two or more of the cut edges. Shared fixes are priced in Phase 5;
  until then `cut_cost` counts edges and is **not** the size of the fix.

Rules:

- **Uncuttable** (`∞`): `PROTECTS`; every edge with no side
  left (§4.2); every edge listed in `remediation.uncuttable_edges` in
  `clapa.yaml`; and every edge on any path that realises a declared
  `intended_access` entry (automatic).
- Costs can be overridden per edge kind (`remediation.cut_costs`, integers ≥ 1);
  an override replaces the edge's cheapest side cost for every edge of that
  kind, but never makes an edge with no side cuttable. The fingerprint never
  depends on these costs (DESIGN.md §8).
- If no finite cut exists, the finding reports **"no fix within constraints"**.
- Ties: the cut is the one closest to the entry (the edges leaving the set the
  entry still reaches in the residual network after the maximum flow), which is
  deterministic because the graph and its arc order are. Not implemented yet: a
  per-edge `cost_source` field, and naming the constraints that block a
  missing fix.

```yaml
remediation:
  cut_costs: { ASSUMES: 7 }
  uncuttable_edges:
    - kind: ASSUMES
      from: "k8s:prod/payments/ServiceAccount/api"
      to:   "arn:aws:iam::111122223333:role/payments-api"
      reason: "payments API identity"
```
