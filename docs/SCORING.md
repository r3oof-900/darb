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

### 4.1 Sides of an edge, and narrowing versus revoking

An edge the evaluator decides has up to two sides, and each side is a separate
fix. A side counts only if deciding the request again **without** that side's
policies no longer grants (ALLOW or UNKNOWN both count as granting); a side
whose removal changes nothing is not a fix. Edges that come from facts (a pod's
service account, a mapping, an RBAC binding) have exactly one side.

A policy side's fix is one of two kinds (decided in the fourth Phase 4 review):

- **narrow**: every statement that grants the edge on that side is *broad*;
  the fix makes it specific (an exact ARN, an exact principal, an
  encryption-context condition). It costs the side's price.
- **revoke**: at least one statement that grants it is *explicit*: it names
  the target and the principal on purpose, so breaking the edge means deleting
  that grant, which may break a function. It costs the side's price **+ 2**.

| Edge | Side | narrow | revoke |
|---|---|---|---|
| `CAN_READ`, `CAN_DECRYPT`, `ASSUMES` (role -> role) | **identity** | **1** | **3** |
| `CAN_READ` (bucket policy), `CAN_DECRYPT` (key policy) | **resource** | **2** | **4** |
| `ASSUMES` (role -> role, IRSA, projected token, Pod Identity, PassRole's service) | **trust** | **5** | **7** |
| `CAN_ESCALATE` (IAM: PassRole, UpdateAssumeRolePolicy, Put/Attach policy, CreatePolicyVersion) | identity | **2** | **4** |

Fact sides have a fixed kind and cost (their price already is that of removing
or turning off something specific):

| Edge | Side | Kind | Cost |
|---|---|---|---|
| `NODE_ROLE`, pod without hostNetwork (require IMDSv2, hop limit 1) | node | narrow | **3** |
| `NODE_ROLE`, hostNetwork pod (turn the node group's metadata endpoint off) | node | revoke | **5** |
| `NODE_ROLE`, hostNetwork pod on a node that already keeps pods out (remove hostNetwork) | workload | revoke | **5** |
| `CAN_ESCALATE` via K8s token (`automountServiceAccountToken: false`) | workload | narrow | **3** |
| `CAN_ESCALATE` via K8s RBAC (remove/limit the binding) | rbac | revoke | **5** |
| `MAPS_TO` (`aws-auth` / access entry) | mapping | revoke | **8** |
| `RUNS_AS` (change the workload's identity) | workload | revoke | **100** |
| `PROTECTS` | none | structural fact, not a permission | **∞** |
| `EXPOSED_TO` (internet -> a publicly exposed workload; remove the exposure: the Service becomes ClusterIP) | exposure | revoke | **20** |
| `CAN_READ_PLAINTEXT` (derived) | none | the cut names the cheaper of its `CAN_READ` / `CAN_DECRYPT` | min of the two |

The edge's capacity is its cheapest side. An edge with no side left is
**uncuttable**: no single change breaks it.

**IMDS and `NODE_ROLE` (Phase 5).** Sources, and what is our reasoning:

- A pod with `hostNetwork: true` uses the node's network namespace
  (Kubernetes API › PodSpec › `hostNetwork`: "Use the host's network
  namespace").
- The PUT response hop limit counts network hops (EC2 User Guide › "Change
  the PUT response hop limit"); EKS recommends IMDSv2 with a hop limit of 1 to
  keep pods off IMDS (EKS Best Practices › "Restrict access to the instance
  profile assigned to the worker node"). That guide does not discuss
  hostNetwork. **Our reasoning:** a hostNetwork pod makes no extra hop, so the
  hop limit does not stop it; the engine models it so (`imdsReachable`).
- IMDSv2 alone does not stop a compromised pod: the session token is obtained
  with a PUT that the pod can make itself; it protects against requests an
  attacker can only relay (SSRF). Under the assume-compromised model a pod is
  the attacker, so IMDSv2 without the hop limit leaves the edge.
- Turning the endpoint off (EC2 User Guide › "Turn off access to instance
  metadata", `http_endpoint = "disabled"`) stops every pod, hostNetwork or
  not, and everything else on the node that uses IMDS: a revoke.

So the fixes of a hostNetwork pod's `NODE_ROLE` are the endpoint off, and,
only when the node already keeps other pods out, removing hostNetwork; the
cheaper fix is usually elsewhere (narrowing the node role, `CAN_READ`
identity, 1). The verifier rejects a hop limit of 1 for scenario 9 and
accepts it for the same pod without hostNetwork (`TestScenario9HopLimit`).

**`EXPOSED_TO` (Phase 5).** The internet reaches each workload behind a
public (or possibly public: NodePort) exposure. Under assume-compromised (the
default) every pod is an entry already, so the edge is never on a path. Without
it, the internet node is the attacker's entry and the cut may take the
exposure, e.g. when intended access makes every IAM edge uncuttable. Its fix
removes the exposure (revoke, 20): an internal scheme alone would leave the
workload an entry of its own (an internal load balancer, exposure 500), the
same path starting there.

**When a statement is explicit.** The granting statements of a side are the
Allow statements of that side's policies that apply to the request (TRUE or
UNKNOWN). A statement is **explicit** when every element below names its value
exactly; otherwise it is **broad** ("a wildcard that matches in general").

| Element | Explicit | Broad |
|---|---|---|
| `Action` | a value equal to the requested action (any case), even beside wildcards (`["s3:*", "s3:GetObject"]`) | only wildcard values (`s3:Get*`, `*`), or `NotAction` |
| `Resource`, S3 read (identity side) | the bucket name is literal and any wildcard is in the object key: a **narrow prefix** is `arn:aws:s3:::B/` followed by at least one character (`B/*`, `B/reports/*`, `B/k.csv`) | a wildcard in the bucket name (`B*/*`, `arn:aws:s3:::*`), `*`, another bucket (`BB/*` does not start with `B/`), or `NotResource` |
| `Resource`, `sts:AssumeRole` and IAM escalations (identity side) | the exact role (or policy) ARN | any wildcard (`role/adm*`, `*`), or `NotResource` |
| `Principal` (resource and trust side) | the exact principal: the role's ARN, or the exact service (`lambda.amazonaws.com`, `pods.eks.amazonaws.com`) | `"*"`, `{"AWS": "*"}`, an account ID or its `root`, another principal, or `NotPrincipal` |
| Web identity trust (IRSA, projected token) | a condition on `<issuer>:sub`, not negated, whose every value is exactly `system:serviceaccount:<ns>:<name>` (also under `StringLike` without a wildcard) | a wildcard `:sub` (`...:payments:*`), a negated operator, or no `:sub` (only `:aud`) |
| `CAN_DECRYPT[for J]` (both sides) | in addition: a condition on `kms:EncryptionContext:aws:s3:arn`, not negated, whose every value is J's ARN or a narrow prefix of its objects (`J/*`) | no such condition (the key's Resource does not decide: the target is J's data), a wildcard (`arn:aws:s3:::*`), a value naming another bucket too, or a negated operator |

On a resource policy the `Resource` element always means the resource the
policy is attached to (a key policy's `"*"` is "this key"), so only `Principal`,
`Action` and, for a decrypt, the context decide. A value holding an unresolved
Terraform placeholder cannot be shown to be broad and counts as explicit. A
side is **revoke** when any of its granting statements is explicit (breaking
the edge must delete it), **narrow** when all are broad, and **revoke** when no
granting statement can be found (it cannot be shown to be broad). Each boundary
above is a test case (`internal/access/fixkind_test.go`).

Examples: scenario 1's `kms:Decrypt` on `"*"` with no context is broad (narrow,
1) while its `s3:GetObject` on the PII bucket's objects is explicit (revoke, 3),
so the decrypt is cut. Scenario 10's key policy grants `Principal: "*"` with
`aws:PrincipalOrgID` (narrow, key policy, 2); the role's explicit read (revoke,
3) is the alternative.

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
the cut is `ASSUMES payments-api -> analytics-admin`, identity side, narrow,
cost 1 (`payments-api` has `sts:AssumeRole` on `"*"`: narrow it to the roles it
needs), with the trust side (cost 5) as the other fix.

### 4.3 What a finding reports

- `chokepoints`: the cut edges; `cut_cost`: the sum of their capacities.
- `fix`: for each cut edge, the side the cut chose (its cheapest), its
  `fix_kind` (`narrow` | `revoke`), the policy to change and its cost;
  `other_side_fix`: the other sides that also break that edge, dearer. The
  console prints a revoke with a warning: *this removes an explicit grant;
  confirm it is not needed*.
- `alternative_fix`: for a cut `CAN_READ_PLAINTEXT`, the other underlying edge
  (whatever its cost, if it can be cut at all); `alternative_fix_detail`: its
  cheapest fix, with side, kind and cost.
- **Tie rule.** When the two underlying edges cost exactly the same, the cut
  names `CAN_DECRYPT[for jewel]` (an encryption-context condition removes
  exactly this path). It is kept only for that case, e.g. `s3:GetObject` and
  `kms:Decrypt` both on `"*"` (both narrow, 1); no fixture uses it, since
  explicit grants cost more (`internal/paths` tests both the tie and a
  cheaper read).
- `shared_fix_possible: [<resource ARN>]`: one change to that resource's policy
  can break two or more of the cut edges. Shared fixes are priced in Phase 5;
  until then `cut_cost` counts edges and is **not** the size of the fix.

Rules:

- **`intended_access` is the strongest constraint**: every edge on any path
  that realises a declared entry is uncuttable, whatever its cost (tested:
  scenario 1 with its read declared intended has no fix).
- **Uncuttable** (`∞`): `PROTECTS`; every edge with no side left (§4.2); every
  edge listed in `remediation.uncuttable_edges` in `clapa.yaml`; and the
  intended-access edges above.
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
