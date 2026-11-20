# Evaluator corpus

Table-driven cases for `internal/eval`, loaded by `corpus_test.go`. Adding a
case needs no Go code. Files are read in name order; the first four cases of
the corpus must be the four same-account resource-policy cases committed to in
`docs/DESIGN.md` section 6.1 (the test enforces this).

## Rules for cases

- `name` is unique and dotted, starting with the documentation it encodes:
  `iam-ug.` (IAM User Guide), `kms-dg.` (KMS Developer Guide), `org-ug.`
  (Organizations User Guide), `eks-ug.`, `s3-ug.`, or `clapa.` for a decision of
  ours recorded in DESIGN.md.
- `doc` names the exact documentation section (or DESIGN.md section).
- At least 150 cases (enforced).

## Format

```yaml
anchors:            # optional; holds YAML anchors (&name) used below. Ignored.
  allowS3: &allowS3 {Effect: Allow, Action: "s3:GetObject", Resource: "*"}

defaults:           # optional; any field a case leaves unset is taken from here
  principal: {kind: assumed-role, arn: "...", account: "111122223333", source: "<role ARN>"}
  action: "s3:GetObject"
  resource: "arn:aws:s3:::data/k"
  resource_account: "111122223333"   # "" = unknown
  context: {default: absent}         # or unknown (the default)
  policies: {resource_policy_required: true}

cases:
  - name: iam-ug.some.rule
    doc: "IAM User Guide › Section › Subsection"
    principal: {...}                 # kind: iam-user | assumed-role | federated-user |
                                     #       root | service | web-identity | anonymous
    context:
      default: absent                # keys not listed: absent or unknown
      present: {"aws:SourceIp": "203.0.113.7", "aws:TagKeys": ["a", "b"]}
      absent: ["aws:SourceVpce"]
      unknown: ["aws:PrincipalOrgID"]
    policies:
      identity: [<policy>, ...]
      resource: [<policy>, ...]
      boundary: <policy>             # omit = no boundary
      session: [<policy>, ...]       # omit = no session policy; [] = one that allows nothing
      scps: [[<policy>, ...], ...]   # one list per organization level; omit = not modelled
      rcps: [[<policy>, ...], ...]
      resource_policy_required: true # KMS keys, role trust policies
    expect: ALLOW | DENY | IMPLICIT_DENY | UNKNOWN
    expect_contributing: ["identity:Sid", "resource:#0"]   # optional, kind:Sid-or-#index
    expect_unresolved: ["Condition:aws:SourceVpce", "Principal"]   # optional
    expect_missing: ["permissions boundary"]                # optional, Component names
```

A `<policy>` is a full document (`{Version, Statement}`), a single statement,
or a list of statements; the last two are wrapped in a `2012-10-17` document.
Quote every string containing `:` or `*`.
