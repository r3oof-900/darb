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
capacity is the cost of the fix that removes it, so the cheapest *disruption*
wins, not the shortest path. Without weights the min-cut would happily cut
`RUNS_AS` or `ASSUMES` — i.e. break the application's own identity.

| Edge kind | Typical fix | Cost |
|---|---|---|
| `CAN_READ`, `CAN_DECRYPT` | narrow `Resource` to exact ARNs; add `kms:EncryptionContext` / `kms:ViaService` condition | **1** (cheap) |
| `CAN_READ` granted to a public principal | replace `"*"` with explicit principals | **2** |
| `CAN_ESCALATE` (IAM permission) | remove the escalation permission | **2** |
| `NODE_ROLE` | require IMDSv2, hop limit 1 | **3** |
| `CAN_ESCALATE` via K8s token (automount) | `automountServiceAccountToken: false` | **3** |
| `ASSUMES` (SA → role, IRSA / Pod Identity) | tighten trust `:sub` / `:aud` | **5** (medium) |
| `ASSUMES` (role → role) | tighten trust principal / add `sts:ExternalId`, `aws:PrincipalArn` conditions | **5** (medium) |
| `CAN_ESCALATE` via K8s RBAC | remove/limit binding (`create pods`, `pods/exec`, `impersonate`, `bind`, `escalate`) | **5** |
| `MAPS_TO` (`aws-auth` / access entry) | remove/narrow the mapping | **8** |
| `EXPOSED_TO` | remove internet exposure | **20** |
| `RUNS_AS` | change the workload's identity | **100** (very expensive) |
| `PROTECTS` | structural fact, not a permission | **∞** (uncuttable) |
| `CAN_READ_PLAINTEXT` (derived) | cut maps to the cheaper of its `CAN_READ` / `CAN_DECRYPT` | min of the two |

Rules:

- **Uncuttable** (`∞`): `PROTECTS`; every edge listed in `remediation.uncuttable_edges`
  in `clapa.yaml`; and every edge on any path that realises a declared
  `intended_access` entry (automatic).
- Costs can be overridden per edge kind (`remediation.cut_costs`); overrides are
  integers ≥ 1.
- If no finite cut exists, the finding reports **"no fix within constraints"** and
  names the constraints (uncuttable entries / intended access) that block it.
- Every fix in every report format lists each cut edge with `kind`, `cost`, and
  `cost_source` (`default` | `config:cut_costs` | `uncuttable:config` |
  `uncuttable:intended_access`), plus the total cost.
- Ties between equal-cost cuts are broken deterministically: fewer edges, then the
  cut closest to the entry point, then lexicographic canonical edge IDs.

```yaml
remediation:
  cut_costs: { ASSUMES: 7 }
  uncuttable_edges:
    - kind: ASSUMES
      from: "k8s:prod/payments/ServiceAccount/api"
      to:   "arn:aws:iam::111122223333:role/payments-api"
      reason: "payments API identity"
```
