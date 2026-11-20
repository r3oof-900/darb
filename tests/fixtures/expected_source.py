"""Hand-written expected findings for every fixture variant.

Written from docs/DESIGN.md section 13.2 (scenario table) and 13.1 (read
audit), and, for posture rules, from reading the fixture files - before any
rule existed (Phase 4). Never generated from tool output; a mismatch is
investigated and shown in review, never fixed here to match the tool.

Each score is worked by hand from docs/SCORING.md (per-mille, floor after
each multiplication); the arithmetic is in the comments. Run
`python tests/fixtures/expected_source.py` to write the expected.json files.
"""
import json
import pathlib

ACCT = "111122223333"
ROLE = f"arn:aws:iam::{ACCT}:role/payments-api"
PII = "arn:aws:s3:::acme-customer-pii"
PII_KEY = f"arn:aws:kms:us-east-1:{ACCT}:key/tf-aws_kms_key.pii"
RECEIPTS_KEY = f"arn:aws:kms:us-east-1:{ACCT}:key/tf-aws_kms_key.receipts"
API = "k8s:prod/payments/Deployment/api"
SA_API = "k8s:prod/payments/ServiceAccount/api"
NS_PAYMENTS = "k8s:prod//Namespace/payments"
ROTATION_DEFAULT = "terraform.aws_kms_key.enable_key_rotation"
S3_DEFAULT = "s3.default-encryption"
AUTOMOUNT_DEFAULT = "k8s.automountServiceAccountToken"
# Group A of the Phase 4 review: every IRSA hop in these fixtures relies on
# two documented defaults (DESIGN.md 4.7): no eks.amazonaws.com/audience
# annotation (audience sts.amazonaws.com) and no OIDC provider in the input
# (its documented audience sts.amazonaws.com). A Pod Identity hop relies on
# disable_session_tags not being set.
OIDC_DEFAULT = "eks.irsa.oidc-provider-audience"
IRSA_DEFAULTS = ["eks.irsa.audience", OIDC_DEFAULT]
POD_IDENTITY_DEFAULTS = ["eks.pod-identity.disableSessionTags"]


def path_finding(rule, entry, jewel, path, score, severity, chokepoints, alternative=None,
                 confirmed=True, confidence="high", defaults=None, fix=None, other_side=None,
                 alternative_detail=None):
    # Phase 5, step 1: every finding with a cut states the side, kind and
    # cost of the chosen fix, of the other sides of the cut edges, and of the
    # alternative's fix (empty lists when there are none), so any change of a
    # cost fails the golden test.
    assert chokepoints == [] or (fix is not None and other_side is not None and alternative_detail is not None), \
        f"{rule} {entry} -> {jewel}: state fix, other_side and alternative_detail"
    return {
        "rule": rule, "entry": entry, "jewel": jewel, "path": path,
        "confirmed": confirmed, "confidence": confidence, "score": score, "severity": severity,
        "chokepoints": chokepoints, "alternative_fix": alternative or [], "defaults_used": defaults or [],
        "fix": fix or [], "other_side_fix": other_side or [], "alternative_fix_detail": alternative_detail or [],
    }


def step(edge, side, kind, cost):
    # One fix of one edge (SCORING.md 4): side, narrow (make a broad grant
    # specific) or revoke (remove an explicit grant, 2 more), and cost.
    return {"edge": edge, "side": side, "fix_kind": kind, "cost": cost}


def posture(rule, resource, score, severity, defaults=None):
    return {"rule": rule, "resource": resource, "score": score, "severity": severity, "defaults_used": defaults or []}


def decrypt_cut(principal, key, jewel):
    # Under a derived read the cut is the cheaper underlying edge; the other
    # one is the alternative fix.
    return [f"CAN_DECRYPT[for {jewel}] {principal} -> {key}"], [f"CAN_READ {principal} -> {jewel}"]


def pii_decrypt_fixes(cut, alt):
    # The PII key fixtures (scenarios 1, 4, 4b, 5, 7, 8, 16, 17), read by hand
    # from their Terraform: the role grants kms:Decrypt (on "*" or on the key
    # ARN) with no kms:EncryptionContext condition, a broad grant: narrow,
    # identity side, 1. aws_kms_key.pii has no policy, so the AWS default key
    # policy applies (Principal: the account root, kms:*), also broad: narrow,
    # key policy, 2. The read is s3:GetObject on the PII bucket's objects
    # ("<bucket ARN>/*"), an explicit grant: revoke, identity side, 3; the
    # bucket has no policy, so the read has no other side.
    return {"fix": [step(cut[0], "identity", "narrow", 1)],
            "other_side": [step(cut[0], "resource", "narrow", 2)],
            "alternative_detail": [step(alt[0], "identity", "revoke", 3)]}


# Scenario 1 path (SCORING.md 1.4): public LoadBalancer (exposure 1000), 3 edges
# (hops 810), no preconditions, all high: likelihood 810; impact pii 900 x
# blast radius 1000 (one jewel) = 900; score 810 x 900 / 1000 = 729, critical.
def classic(entry=API, sa=SA_API, role=ROLE, defaults=None):
    cut, alt = decrypt_cut(role, PII_KEY, PII)
    return path_finding("CLAPA-PATH-001", entry, PII,
                        [f"RUNS_AS {sa}", f"ASSUMES {role}", f"CAN_READ_PLAINTEXT {PII}"],
                        729, "critical", cut, alt, defaults=IRSA_DEFAULTS if defaults is None else defaults,
                        **pii_decrypt_fixes(cut, alt))


# CLAPA-POST-007: base medium 350, confidence medium 700: 350 x 700 / 1000 = 245, low.
def no_default_deny(ns):
    return posture("CLAPA-POST-007", ns, 245, "low")


# CLAPA-POST-006: base medium 350, confidence high: 350, medium.
def rotation_off(key, defaulted=True):
    return posture("CLAPA-POST-006", key, 350, "medium", [ROTATION_DEFAULT] if defaulted else [])


ABSENT_PII = [{"rule": "CLAPA-PATH-001", "jewel": PII}, {"rule": "CLAPA-PATH-002", "jewel": PII}]

E = {}

# 1 - IRSA -> role -> kms:Decrypt on * -> CMK -> PII bucket.
# Cut (fourth Phase 4 review, SCORING.md 4.1): kms:Decrypt on "*" with no
# encryption context is broad: narrow it, identity side, cost 1. The read is
# s3:GetObject on the PII bucket's objects, an explicit grant (revoke, 3), so
# the decrypt is cheaper and no tie rule is needed.
E["01_classic/vulnerable"] = {"derived_from": "13.2 row 1; 13.1",
                              "findings": [classic(),
                                           no_default_deny(NS_PAYMENTS)]}
E["01_classic/fixed"] = {"derived_from": "13.2 row 1 fixed: reads only the receipts bucket, decrypt scoped by encryption context",
                         "findings": [rotation_off(RECEIPTS_KEY), no_default_deny(NS_PAYMENTS)], "absent": ABSENT_PII}

# 2 - split in the Phase 4 review into 2a, 2b, 2c. Read + decrypt on A
# only; A is intended access; nothing reaches B. The decrypt grant must use
# the encryption context S3 actually sends: the bucket ARN with an S3
# Bucket Key, the object ARN without one (S3 User Guide, Encryption context).
def intended(status):
    return [{"principal": API, "action": "s3:GetObject", "resource": "arn:aws:s3:::acme-payment-receipts/*", "status": status}]


SCENARIO2 = {
    "02a_ec_bucket_key": ("13.2 row 2a: Bucket Key on, StringEquals on bucket A's ARN", "verified", "verified"),
    "02b_ec_object_arn": ("13.2 row 2b: no Bucket Key, StringLike on arn:aws:s3:::A/*", "verified", "verified"),
    "02c_ec_mismatch": ("13.2 row 2c: no Bucket Key, StringEquals on bucket A's ARN: the declared access is not satisfied", "not-satisfied", "verified"),
}
for name, (why, vulnerable, fixed) in SCENARIO2.items():
    for v, status in (("vulnerable", vulnerable), ("fixed", fixed)):
        E[f"{name}/{v}"] = {
            "derived_from": why + ("" if v == "vulnerable" else " (fixed)"),
            "findings": [rotation_off(RECEIPTS_KEY), no_default_deny(NS_PAYMENTS)],
            "absent": ABSENT_PII, "intended_access": intended(status)}

# 3 - decrypt on B's key only with another bucket's encryption context: no path.
for v in ("vulnerable", "fixed"):
    E[f"03_ec_other_bucket/{v}"] = {"derived_from": f"13.2 row 3 ({v})",
                                    "findings": [no_default_deny(NS_PAYMENTS)], "absent": ABSENT_PII}

# 4, 5 - wildcard :sub / :aud only: a path from every service account's
# workload. tools/debug runs as tools/default, not exposed (exposure 400):
# likelihood 400 x 810 = 324; 324 x 900 = 291, medium.
# CLAPA-POST-001: base high 600, confidence high: 600, high.
NS_TOOLS = "k8s:prod//Namespace/tools"
for n, row in (("04_wildcard_sub", 4), ("05_aud_only", 5)):
    cut, alt = decrypt_cut(ROLE, PII_KEY, PII)
    debug = path_finding("CLAPA-PATH-001", "k8s:prod/tools/Deployment/debug", PII,
                         ["RUNS_AS k8s:prod/tools/ServiceAccount/default", f"ASSUMES {ROLE}", f"CAN_READ_PLAINTEXT {PII}"],
                         291, "medium", cut, alt, defaults=IRSA_DEFAULTS, **pii_decrypt_fixes(cut, alt))
    E[f"{n}/vulnerable"] = {"derived_from": f"13.2 row {row}",
                            "findings": [classic(), debug, posture("CLAPA-POST-001", ROLE, 600, "high"),
                                         no_default_deny(NS_PAYMENTS), no_default_deny(NS_TOOLS)]}
    E[f"{n}/fixed"] = {"derived_from": f"13.2 row {row} fixed: :sub pinned to payments/api",
                       "findings": [classic(), no_default_deny(NS_PAYMENTS), no_default_deny(NS_TOOLS)],
                       "absent": [{"rule": "CLAPA-PATH-001", "entry": "k8s:prod/tools/Deployment/debug", "jewel": PII},
                                  {"rule": "CLAPA-POST-001", "resource": ROLE}]}

# 4b - added in the Phase 4 review: a service account without annotation
# whose Role may create pods in its namespace mints an sts.amazonaws.com
# token for itself (CAN_ESCALATE[k8s-token], then ASSUMES via the minted
# token) and the wildcard trust accepts it. builder is not exposed (400),
# 3 edges (810): 324; 324 x 900 = 291, medium. The token is mounted by
# default; the OIDC provider is not in the input, so its audience is the
# documented sts.amazonaws.com.
BUILDER = "k8s:prod/tools/Deployment/builder"
NS_TOOLS_4B = "k8s:prod//Namespace/tools"
cut, alt = decrypt_cut(ROLE, PII_KEY, PII)
E["04b_create_pods_wildcard/vulnerable"] = {"derived_from": "13.2 row 4b (Phase 4 review)", "findings": [
    path_finding("CLAPA-PATH-002", BUILDER, PII,
                 ["CAN_ESCALATE k8s:prod/tools/ServiceAccount/builder", f"ASSUMES {ROLE}", f"CAN_READ_PLAINTEXT {PII}"],
                 291, "medium", cut, alt, defaults=[OIDC_DEFAULT, AUTOMOUNT_DEFAULT], **pii_decrypt_fixes(cut, alt)),
    posture("CLAPA-POST-001", ROLE, 600, "high"),
    posture("CLAPA-POST-004", BUILDER, 350, "medium", [AUTOMOUNT_DEFAULT]),
    no_default_deny(NS_TOOLS_4B)]}
E["04b_create_pods_wildcard/fixed"] = {"derived_from": "13.2 row 4b fixed: :sub pinned to payments/api", "findings": [
    posture("CLAPA-POST-004", BUILDER, 350, "medium", [AUTOMOUNT_DEFAULT]), no_default_deny(NS_TOOLS_4B)],
    "absent": [{"rule": "CLAPA-PATH-002", "entry": BUILDER, "jewel": PII}, {"rule": "CLAPA-POST-001", "resource": ROLE}]}

# 6 - sts:AssumeRole on * -> AdministratorAccess role in account B -> PII in B.
# 4 edges (hops 729), exposure 1000: likelihood 729; 729 x 900 = 656, high.
B = "444455556666"
ADMIN = f"arn:aws:iam::{B}:role/analytics-admin"
WAREHOUSE = "arn:aws:s3:::acme-analytics-warehouse"
WAREHOUSE_KEY = f"arn:aws:kms:us-east-1:{B}:key/tf-aws_kms_key.warehouse"
# Cut (third Phase 4 review, SCORING.md 4.2): analytics-admin can rewrite its
# own policies, the warehouse key policy and the bucket policy, so no cut after
# it holds. The cut is the hop into it, identity side, cost 1: remove
# sts:AssumeRole from payments-api (sts:AssumeRole on "*" is broad: narrow it
# to the roles it needs); the trust side, cost 5, is the other fix. No derived edge is cut, so no alternative_fix.
CHAIN = f"ASSUMES {ROLE} -> {ADMIN}"
E["06_role_chain_cross_account/vulnerable"] = {"derived_from": "13.2 row 6", "findings": [
    path_finding("CLAPA-PATH-001", API, WAREHOUSE,
                 [f"RUNS_AS {SA_API}", f"ASSUMES {ROLE}", f"ASSUMES {ADMIN}", f"CAN_READ_PLAINTEXT {WAREHOUSE}"],
                 656, "high", [CHAIN], [], defaults=IRSA_DEFAULTS,
                 fix=[step(CHAIN, "identity", "narrow", 1)],
                 # analytics-admin's trust names Principal arn:aws:iam::111122223333:root,
                 # an account: broad, narrow, trust side, 5.
                 other_side=[step(CHAIN, "trust", "narrow", 5)], alternative_detail=[]),
    rotation_off(WAREHOUSE_KEY), no_default_deny(NS_PAYMENTS)]}
E["06_role_chain_cross_account/fixed"] = {"derived_from": "13.2 row 6 fixed: AssumeRole scoped to one role in account A",
                                          "findings": [rotation_off(WAREHOUSE_KEY), no_default_deny(NS_PAYMENTS)],
                                          "absent": [{"rule": "CLAPA-PATH-001", "jewel": WAREHOUSE}]}

# 7 - iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction -> role reading PII.
# 4 edges, exposure 1000: 729 x 900 = 656, high.
PROCESSOR = f"arn:aws:iam::{ACCT}:role/data-processor"
cut, alt = decrypt_cut(PROCESSOR, PII_KEY, PII)
E["07_passrole_lambda/vulnerable"] = {"derived_from": "13.2 row 7", "findings": [
    path_finding("CLAPA-PATH-002", API, PII,
                 [f"RUNS_AS {SA_API}", f"ASSUMES {ROLE}", f"CAN_ESCALATE {PROCESSOR}", f"CAN_READ_PLAINTEXT {PII}"],
                 656, "high", cut, alt, defaults=IRSA_DEFAULTS, **pii_decrypt_fixes(cut, alt)),
    no_default_deny(NS_PAYMENTS)]}
E["07_passrole_lambda/fixed"] = {"derived_from": "13.2 row 7 fixed: PassRole scoped and conditioned, no InvokeFunction",
                                 "findings": [no_default_deny(NS_PAYMENTS)], "absent": ABSENT_PII}

# 8 - RBAC create pods in payments; SA api there has an IRSA role reading PII.
# ci-runner (not exposed, 400) uses its mounted token (automount: default true),
# creates a pod as api, which assumes the role: 4 edges (729):
# 400 x 729 = 291; 291 x 900 = 261, medium.
# The api workload's own read of PII (scenario 1 shape, 729) is in both variants.
# CLAPA-POST-004 on ci-runner: base medium 350, confidence high: 350, medium.
CI = "k8s:prod/payments/Deployment/ci-runner"
SA_CI = "k8s:prod/payments/ServiceAccount/ci"
cut, alt = decrypt_cut(ROLE, PII_KEY, PII)
E["08_rbac_create_pods/vulnerable"] = {"derived_from": "13.2 row 8", "findings": [
    classic(),
    path_finding("CLAPA-PATH-002", CI, PII,
                 [f"CAN_ESCALATE {SA_CI}", f"CAN_ESCALATE {SA_API}", f"ASSUMES {ROLE}", f"CAN_READ_PLAINTEXT {PII}"],
                 261, "medium", cut, alt, defaults=IRSA_DEFAULTS + [AUTOMOUNT_DEFAULT], **pii_decrypt_fixes(cut, alt)),
    posture("CLAPA-POST-004", CI, 350, "medium", [AUTOMOUNT_DEFAULT]),
    no_default_deny(NS_PAYMENTS)]}
E["08_rbac_create_pods/fixed"] = {"derived_from": "13.2 row 8 fixed: get/list/watch only", "findings": [
    classic(), posture("CLAPA-POST-004", CI, 350, "medium", [AUTOMOUNT_DEFAULT]), no_default_deny(NS_PAYMENTS)],
    "absent": [{"rule": "CLAPA-PATH-002", "entry": CI, "jewel": PII}]}

# 9 - hostNetwork DaemonSet + IMDSv1 -> node role -> s3:GetObject on * -> SSE-S3 PII.
# Not exposed (400), 2 edges (900), NODE_ROLE precondition known satisfied (900):
# 400 x 900 = 360; 360 x 900 = 324; x confidence 1000 = 324; 324 x 900 = 291, medium.
# The bucket states no encryption: SSE-S3 by documented default.
# CLAPA-POST-002: base high 600: high.
NODE = f"arn:aws:iam::{ACCT}:role/eks-node"
EXPORTS = "arn:aws:s3:::acme-customer-exports"
NS_MON = "k8s:prod//Namespace/monitoring"
E["09_hostnetwork_imds/vulnerable"] = {"derived_from": "13.2 row 9", "findings": [
    path_finding("CLAPA-PATH-001", "k8s:prod/monitoring/DaemonSet/node-monitor", EXPORTS,
                 [f"NODE_ROLE {NODE}", f"CAN_READ_PLAINTEXT {EXPORTS}"], 291, "medium",
                 [f"CAN_READ {NODE} -> {EXPORTS}"], defaults=[S3_DEFAULT],
                 # The node role grants s3:GetObject on "*": broad, narrow, identity, 1.
                 # The exports bucket has no policy and no KMS key: no other side, no alternative.
                 fix=[step(f"CAN_READ {NODE} -> {EXPORTS}", "identity", "narrow", 1)], other_side=[], alternative_detail=[]),
    posture("CLAPA-POST-002", "eks-nodegroup:prod/default", 600, "high"),
    no_default_deny(NS_MON)]}
E["09_hostnetwork_imds/fixed"] = {"derived_from": "13.2 row 9 fixed: IMDSv2 required, hop limit 1, no hostNetwork",
                                  "findings": [no_default_deny(NS_MON)],
                                  "absent": [{"rule": "CLAPA-PATH-001", "jewel": EXPORTS},
                                             {"rule": "CLAPA-POST-002", "resource": "eks-nodegroup:prod/default"}]}

# 10 - decrypt only from a key policy with aws:PrincipalOrgID, org not configured:
# UNKNOWN, unconfirmed, confidence low (400): 1000 x 810 = 810; 810 x 400 = 324;
# 324 x 900 = 291, medium.
# Cut (fourth Phase 4 review): the role has no kms:Decrypt of its own; the
# key policy grants it to Principal "*" with aws:PrincipalOrgID, a broad
# grant: narrow the key policy, cost 2. The alternative is the read, an
# explicit s3:GetObject on the bucket's objects: revoke, identity side, 3.
SHARED_KEY = f"arn:aws:kms:us-east-1:{ACCT}:key/tf-aws_kms_key.shared"
cut, alt = decrypt_cut(ROLE, SHARED_KEY, PII)
E["10_kms_principal_org_id/vulnerable"] = {"derived_from": "13.2 row 10 (no organization ID configured)", "findings": [
    path_finding("CLAPA-PATH-001", API, PII, [f"RUNS_AS {SA_API}", f"ASSUMES {ROLE}", f"CAN_READ_PLAINTEXT {PII}"],
                 291, "medium", cut, alt, confirmed=False, confidence="low", defaults=IRSA_DEFAULTS,
                 fix=[step(cut[0], "resource", "narrow", 2)], other_side=[],
                 alternative_detail=[step(alt[0], "identity", "revoke", 3)]),
    rotation_off(SHARED_KEY), no_default_deny(NS_PAYMENTS)]}
E["10_kms_principal_org_id/fixed"] = {"derived_from": "13.2 row 10 fixed: key policy names the reporter role",
                                      "findings": [rotation_off(SHARED_KEY), no_default_deny(NS_PAYMENTS)],
                                      "absent": ABSENT_PII}

# 11 - scenario 1 grants plus a boundary Deny: no path.
for v in ("vulnerable", "fixed"):
    E[f"11_boundary_deny/{v}"] = {"derived_from": f"13.2 row 11 ({v})",
                                  "findings": [no_default_deny(NS_PAYMENTS)], "absent": ABSENT_PII}

# 12 - anonymous read: 1 edge, exposure 1000: likelihood 1000; 1000 x 900 = 900,
# critical. Cut: CAN_READ granted to a public principal, cost 2.
# CLAPA-POST-005: base high 600: high.
LEADS = "arn:aws:s3:::acme-marketing-leads"
E["12_public_bucket/vulnerable"] = {"derived_from": "13.2 row 12", "findings": [
    path_finding("CLAPA-PATH-003", "anonymous", LEADS, [f"CAN_READ_PLAINTEXT {LEADS}"], 900, "critical",
                 [f"CAN_READ anonymous -> {LEADS}"], defaults=[S3_DEFAULT],
                 # The bucket policy grants Principal "*": broad, narrow, bucket policy, 2.
                 # The anonymous caller has no identity policy: no other side.
                 fix=[step(f"CAN_READ anonymous -> {LEADS}", "resource", "narrow", 2)], other_side=[], alternative_detail=[]),
    posture("CLAPA-POST-005", LEADS, 600, "high")]}
E["12_public_bucket/fixed"] = {"derived_from": "13.2 row 12 fixed: Block Public Access on, policy names one role",
                               "findings": [], "absent": [{"rule": "CLAPA-PATH-003", "jewel": LEADS},
                                                          {"rule": "CLAPA-POST-005", "resource": LEADS}]}

# 13 - module + for_each -> 3 IRSA roles for 3 SAs, SSE-S3 PII bucket.
# Plan: CronJobs are not exposed (400), 3 edges (810): 400 x 810 = 324;
# 324 x 900 = 291, medium; cut CAN_READ (no decrypt under SSE-S3).
# Static: role names unresolved -> UNKNOWN, confidence low:
# 324 x 400 = 129; 129 x 900 = 116, low; exit 3 at default tolerance (the
# unconfirmed findings are below the default --fail-on high).
NS_ANALYTICS = "k8s:prod//Namespace/analytics"
def reader(name, static=False):
    role = f"arn:aws:iam::{ACCT}:role/reader-" + ("${clapa:unresolved:each.value}" if static else name)
    return path_finding("CLAPA-PATH-001", f"k8s:prod/analytics/CronJob/{name}", PII,
                        [f"RUNS_AS k8s:prod/analytics/ServiceAccount/{name}", f"ASSUMES {role}", f"CAN_READ_PLAINTEXT {PII}"],
                        116 if static else 291, "low" if static else "medium", [f"CAN_READ {role} -> {PII}"],
                        confirmed=not static, confidence="low" if static else "high", defaults=IRSA_DEFAULTS,
                        # s3:GetObject on "arn:aws:s3:::${var.bucket}/*": the plan resolves it
                        # to the PII bucket's objects, explicit; statically var.bucket is
                        # unresolved, which cannot be shown broad (SCORING.md 4.1). Either
                        # way: revoke, identity, 3. SSE-S3 and no bucket policy: nothing else.
                        fix=[step(f"CAN_READ {role} -> {PII}", "identity", "revoke", 3)], other_side=[], alternative_detail=[])
READERS = ("etl", "bi", "ml")
E["13_module_for_each/vulnerable"] = {"derived_from": "13.2 row 13 (plan mode)",
                                      "findings": [reader(n) for n in READERS] + [no_default_deny(NS_ANALYTICS)]}
E["13_module_for_each/fixed"] = {"derived_from": "13.2 row 13 fixed (plan mode): roles read a non-PII bucket",
                                 "findings": [no_default_deny(NS_ANALYTICS)],
                                 "absent": [{"rule": "CLAPA-PATH-001", "jewel": PII}]}
STATIC = {}
for v, why in (("vulnerable", "13.2 row 13 (static mode)"),
               ("fixed", "13.2 row 13 (static mode): the module's var.bucket is not resolved statically, so the fixed roles' bucket is as unknown as the vulnerable ones'")):
    STATIC[f"13_module_for_each/{v}"] = {"derived_from": why, "exit_code": 3,
                                         "findings": [reader(n, static=True) for n in READERS] + [no_default_deny(NS_ANALYTICS)]}

# 14 - same role name (and bucket-name suffix) in two accounts, each role
# reading its own account's SSE-S3 bucket: two distinct nodes, two findings
# with distinct fingerprints, and (Phase 4 review, D) nothing crossing from
# one account to the other account's same-named resources. app-a and app-b
# are not exposed (400), 3 edges (810): 324; 324 x 900 = 291, medium; the
# cut is the read (SSE-S3, no decrypt). Both IRSA paths rely on the
# documented audience defaults.
def own(acct, sa):
    role, bucket = f"arn:aws:iam::{acct}:role/app", f"arn:aws:s3:::data-{acct}"
    return path_finding("CLAPA-PATH-001", f"k8s:prod/apps/Deployment/{sa}", bucket,
                        [f"RUNS_AS k8s:prod/apps/ServiceAccount/{sa}", f"ASSUMES {role}", f"CAN_READ_PLAINTEXT {bucket}"],
                        291, "medium", [f"CAN_READ {role} -> {bucket}"], defaults=IRSA_DEFAULTS,
                        # The inline policy "data" grants s3:GetObject on "arn:aws:s3:::data-<acct>/*":
                        # explicit, revoke, identity, 3. SSE-S3, no bucket policy: nothing else.
                        fix=[step(f"CAN_READ {role} -> {bucket}", "identity", "revoke", 3)], other_side=[], alternative_detail=[])
NO_CROSSING = [
    {"from": f"arn:aws:iam::{ACCT}:role/app", "to": f"arn:aws:s3:::data-{B}"},
    {"from": f"arn:aws:iam::{B}:role/app", "to": f"arn:aws:s3:::data-{ACCT}"},
    {"from": "k8s:prod/apps/ServiceAccount/app-a", "to": f"arn:aws:iam::{B}:role/app"},
    {"from": "k8s:prod/apps/ServiceAccount/app-b", "to": f"arn:aws:iam::{ACCT}:role/app"},
]
CROSS_ABSENT = [
    {"rule": "CLAPA-PATH-001", "entry": "k8s:prod/apps/Deployment/app-a", "jewel": f"arn:aws:s3:::data-{B}"},
    {"rule": "CLAPA-PATH-001", "entry": "k8s:prod/apps/Deployment/app-b", "jewel": f"arn:aws:s3:::data-{ACCT}"},
]
NS_APPS = "k8s:prod//Namespace/apps"
E["14_same_names_two_accounts/vulnerable"] = {"derived_from": "13.2 row 14 (entries added in the Phase 4 review)", "distinct_fingerprints": True,
                                              "findings": [own(ACCT, "app-a"), own(B, "app-b"), no_default_deny(NS_APPS)],
                                              "absent": CROSS_ABSENT, "no_edges": NO_CROSSING}
E["14_same_names_two_accounts/fixed"] = {"derived_from": "13.2 row 14 fixed: account 444455556666's role can only list",
                                         "findings": [own(ACCT, "app-a"), no_default_deny(NS_APPS)],
                                         "absent": CROSS_ABSENT + [{"rule": "CLAPA-PATH-001", "jewel": f"arn:aws:s3:::data-{B}"}],
                                         "no_edges": NO_CROSSING}

# 15 - empty input: exit 3, nothing collected, never "0 findings".
E["15_empty_input/vulnerable"] = {"derived_from": "13.2 row 15", "exit_code": 3, "collected": 0, "findings": []}
E["15_empty_input/fixed"] = {"derived_from": "13.2 row 15 fixed: one namespace manifest, no workloads", "findings": []}

# 16 - malformed YAML and HCL next to a valid copy of scenario 1.
E["16_malformed_inputs/vulnerable"] = {"derived_from": "13.2 row 16",
                                       "parse_errors": ["k8s/broken.yaml", "terraform/broken.tf"],
                                       "findings": [classic(), no_default_deny(NS_PAYMENTS)]}
E["16_malformed_inputs/fixed"] = {"derived_from": "13.2 row 16 fixed: valid files only",
                                  "findings": [classic(), no_default_deny(NS_PAYMENTS)]}

# 17 - scenario 1 through EKS Pod Identity.
E["17_pod_identity_classic/vulnerable"] = {"derived_from": "13.2 row 17", "findings": [classic(defaults=POD_IDENTITY_DEFAULTS), no_default_deny(NS_PAYMENTS)]}
E["17_pod_identity_classic/fixed"] = {"derived_from": "13.2 row 17 fixed (as scenario 1 fixed)",
                                      "findings": [rotation_off(RECEIPTS_KEY), no_default_deny(NS_PAYMENTS)],
                                      "absent": ABSENT_PII}


def write(name, doc):
    out = {"format": "clapa-expected/v1"}
    out.update(doc)
    out.setdefault("absent", [])
    out.setdefault("intended_access", [])
    out.setdefault("no_edges", [])
    p = pathlib.Path(__file__).parent / name
    p.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    for variant, doc in sorted(E.items()):
        write(f"{variant}/expected.json", doc)
    for variant, doc in sorted(STATIC.items()):
        write(f"{variant}/expected.static.json", doc)
    print(len(E) + len(STATIC), "files")
