# FAQ

## Results

### Why is a finding "unconfirmed" and still critical?

Because something on its path is not known, and darb scores the worst case
of every unknown ([DESIGN.md §6.2](DESIGN.md#62-three-valued-logic-unknown)).
The status says how sure the path is, the severity how bad it is if the
unknowns go the attacker's way:

| Status | Meaning |
|---|---|
| `confirmed` | every step is decided |
| `confirmed_unless_denied` | every required Allow is known; only a Deny that could not be evaluated stands in the way |
| `unconfirmed` | a step needs an Allow (or a fact) that is not known |

The finding's `undecided` list names each unknown and what resolves it: a
managed-policy refresh, an `assume:` entry in `darb.yaml` for a context
key, a `--plan` for a value only Terraform knows, or the missing input.
Resolve them and rescan; a severity can then go down, never up.

### The scan found nothing. Am I secure?

darb never says so. An empty result means "no path in what was scanned";
the report lists the coverage it rests on (inputs, gaps, `not-modelled`
notes). With nothing collected, the console says so and the exit code is 3.
Exit 0 also requires coverage within tolerance (default: no gap).

### Why is a bucket nobody tagged reported?

A data store (an S3 bucket, a Secrets Manager secret, a SecureString
parameter, a Kubernetes Secret) that no tag or `crown_jewels.explicit` entry
classifies may hold anything, so darb does not drop it: it is a crown jewel of
classification `unclassified`, valued 400 like `internal` (a path to one is at
most medium), not counted in blast radius, with no posture rules. The report
names every such store in one note: tag them, or list them in
`crown_jewels.explicit`. To scan classified data only, set
`crown_jewels.unclassified: ignore`; the note then says which stores were not
scanned. A workload's read declared in `intended_access` is not reported.

### Why exit code 3 when there are no findings?

The scan is incomplete: a coverage gap above the tolerance in `darb.yaml`
(for example an unresolved Terraform variable), or no input at all. Findings
take precedence (exit 1): they are actionable even when coverage is partial.

### Why is a path reported that an SCP would block?

AWS Organizations SCPs and RCPs are not collected yet. They can only restrict
access, so without them darb may report a path that one of them blocks; they
never hide one. Every scan with AWS data says so in a `not-modelled` note.

### Can darb miss a path?

Yes, through what it does not collect yet:

- **KMS grants it cannot see.** Grants are collected and evaluated, but a
  Terraform scan does not see the grants AWS services create at runtime, and a
  key whose `ListGrants` failed has none in the input. A grant can give
  `kms:Decrypt` to a principal that the key policy does not name; the note
  names these keys.
- **S3 object ACLs.** With ACLs enabled, an object's ACL can give anyone or
  another account read access to it; darb does not read objects, so each such
  bucket gets a coverage gap. A bucket ACL is not a read: its `READ` only
  lists objects. A bucket with `BucketOwnerEnforced` has ACLs disabled and
  nothing to miss.
- **AWS RAM shares of SSM parameters.** A share can give another account read
  access that the parameter's resource policies do not show.

Each report names the keys, buckets and shareable parameters these concern in
`not-modelled` notes; the notes do not change the exit code. The full list,
with whether each can hide a path, is [DESIGN.md §12.3](DESIGN.md#123-limits-every-report-states-phase-7).

### Why is a role with an AWS managed policy UNKNOWN?

The bundled managed-policy snapshot is IAM's list of every AWS managed
policy at its default version on 2026-11-23 (1622 policies). A policy AWS
published after that is not in it: an attached one is an unknown Allow and
Deny, never "no permissions", and the report warns about each one until
`tools/refresh-managed-policies` runs again
([DESIGN.md §12.1](DESIGN.md#121-known-constraints-carried-between-phases)).
A policy AWS changed after that is read at its 2026-11-23 version.

### Are fingerprints stable?

Yes, across scans and machines: a fingerprint is a hash of the rule ID, the
rule's major version and the finding's identity (entry and jewel for a path,
the resource for a misconfiguration), not of a file path or a line. Two scans
of the same input are byte-identical unless `--timestamps` is given.

## Fixes

### What is the "cheapest fix"?

The smallest set of changes that breaks every path of the finding (a weighted
minimum cut, [SCORING.md §4](SCORING.md)). Narrowing a broad grant costs
less than revoking an explicit one; a resource policy costs more than an
identity policy when both work. The report also gives an alternative fix
that shares no change with the chosen one, when there is one.

### Root cause or mitigation?

`darb remediate` (or `scan --fixes`) labels each verified fix. A
**root-cause** fix removes the broad grant; a **mitigation** blocks this path
only and leaves the broad grant in place, which other paths may use. Root
causes are offered first.

### What is a "resolve" step?

A change darb cannot price because the grant it would change is not known
(an unknown Allow). It costs nothing and changes nothing: it names the command
that decides the unknown. A fix with such a step is
`partial_pending_resolution`: resolve, rescan, and the fix may need more
steps.

### Does `remediate --write` change my cloud?

No. It writes to your Terraform or manifest files, only when the fix is
verified both in memory and by rescanning the patched files, only into a
clean git tree (unless `--force`), and a revoke needs `--allow-revoke`. It
never calls a cloud API. Live input has no files to patch: run
`collect-snapshot` and remediate the snapshot to see the policy to apply.

## Triage

### How do I accept a finding?

Add it to `.darb-ignore.yaml` (or `--ignore FILE`) with a reason, an owner
and an expiry date:

```yaml
suppressions:
  - {fingerprint: b2113156f5b8e654..., reason: "break-glass role, reviewed", owner: platform-team, expires: "2027-03-31"}
```

A missing field is a configuration error. A suppressed finding is listed in
the report and does not count for the exit code; after `expires` it fires
again and the console warns.

### How do I fail CI only on new findings?

`darb scan ... --baseline previous.json --fail-on high`: only findings not in
the previous JSON report are reported and decide the exit code; the ones that
are gone are listed as resolved.

### How do I see results in GitHub code scanning?

`--format sarif --output darb.sarif`, then upload it with
`github/codeql-action/upload-sarif`. Paths appear as code flows, and darb's
fingerprint is the SARIF `partialFingerprints`.

## Privacy

### Does darb send anything anywhere?

Only to the cloud APIs it reads (live scans, read-only) and, when you pass
`--llm`, to that LLM provider. No telemetry, no update check.

### What does `--llm` send?

Structured fields of the report for each attack path (rule, severity, score,
status, entry, jewel, path, undecided, cheapest fix, defaults relied on), with
every secret redacted. Never a file of your input, never a policy document.
With `--llm-redact-identifiers`, account IDs, ARNs and names are replaced by
tokens such as `arn-0001` and restored locally. Misconfigurations are not
sent. The answer is labelled "AI-generated explanation" and never changes a
verdict, a score or a fix. See [THREAT_MODEL.md](THREAT_MODEL.md).

### Where does the API key go?

`ANTHROPIC_API_KEY` in the environment only; there is no flag for it. It is
never printed, logged or written to a report.
