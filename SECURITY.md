# Security policy

## Reporting a vulnerability

Please **do not** open a public issue, pull request or discussion. Report
privately through GitHub's *Private vulnerability reporting*:
<https://github.com/r3oof-900/clapa/security/advisories/new> (or the
repository's **Security** tab → **Report a vulnerability**). Only the
maintainers see the report and the conversation that follows.

Include the affected version (`clapa version`), a description, and a minimal
reproduction (sanitise any real account IDs, ARNs or secrets).

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment and severity | within 10 business days |
| Fix or mitigation | as fast as severity requires; coordinated disclosure within 90 days |

We credit reporters in the advisory unless you ask us not to.

## Supported versions

Before 1.0, only the latest release receives security fixes.

## Scope

In scope: the `clapa` binary, its report outputs (e.g. HTML injection), its
handling of inputs and credentials, and the release pipeline. The tool's own
threat model is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

Note: CLAPA reports describe how an environment could be breached. Treat them
as sensitive.
