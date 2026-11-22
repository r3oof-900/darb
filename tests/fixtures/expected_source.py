"""Hand-written expected findings for every fixture variant.

Written from docs/DESIGN.md section 13.2 (scenario table) and 13.1 (read
audit), and, for posture rules, from reading the fixture files - before any
rule existed (Phase 4). Never generated from tool output; a mismatch is
investigated and shown in review, never fixed here to match the tool.

Each score is worked by hand from docs/SCORING.md (per-mille, floor after
each multiplication); the arithmetic is in the comments. Run
`python tests/fixtures/expected_source.py` to write the expected.json files.
"""
import hashlib
import json
import pathlib

ACCT = "111122223333"
ROLE = f"arn:aws:iam::{ACCT}:role/payments-api"
# Phase 6 (cluster identity by ARN, DESIGN.md 5): a Kubernetes identity is
# k8s:{cluster key}/{namespace}/{kind}/{name}, the key being the cluster's
# ARN when its account and region are known. Every scenario with Kubernetes
# input declares prod in 111122223333, us-east-1 in its darb.yaml, so its
# key is this ARN; it is derived from darb.yaml, not read from the tool.
PROD = f"arn:aws:eks:us-east-1:{ACCT}:cluster/prod"
PII = "arn:aws:s3:::acme-customer-pii"
PII_KEY = f"arn:aws:kms:us-east-1:{ACCT}:key/tf-aws_kms_key.pii"
RECEIPTS_KEY = f"arn:aws:kms:us-east-1:{ACCT}:key/tf-aws_kms_key.receipts"
API = f"k8s:{PROD}/payments/Deployment/api"
SA_API = f"k8s:{PROD}/payments/ServiceAccount/api"
NS_PAYMENTS = f"k8s:{PROD}//Namespace/payments"
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
                 alternative_detail=None, status=None, undecided=None, also_fixes=None, uncuttable=None,
                 shared_fix=None):
    # Phase 6 review (DESIGN.md 6.2, SCORING.md 1): the score is the worst
    # case of every unknown; the status says what kind of unknown there is.
    status = status or ("confirmed" if confirmed else "unconfirmed")
    assert confirmed == (status == "confirmed")
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
        "status": status, **({"undecided": undecided} if undecided else {}),
        # Phase 6 review: the findings of other rules the cut also fixes, and
        # the underlying edges of a cut derived read that no change breaks.
        "also_fixes": also_fixes or [], "uncuttable": [{"edge": e} for e in (uncuttable or [])],
        # Phase 6 review: the policies one change to which breaks two or more
        # cut edges (stated where derived).
        **({"shared_fix_possible": shared_fix} if shared_fix is not None else {}),
        # Round 7: a cut with a resolve step is pending resolution.
        **({"remediation_status": "partial_pending_resolution"
            if any(x["fix_kind"] == "resolve" for x in fix or []) else "complete"} if chokepoints else {}),
    }


def step(edge, side, kind, cost, policy=None, resolve=None):
    # One fix of one edge (SCORING.md 4): side, narrow (make a broad grant
    # specific) or revoke (remove an explicit grant, 2 more), and cost.
    # Phase 6 review: a detach of an AWS managed policy names the policy;
    # it is one change however many edges it breaks.
    # Round 7: a side resting only on an unknown Allow is resolved (cost 0,
    # no patch), naming the command that decides it.
    assert (kind == "resolve") == (resolve is not None) and (kind != "resolve" or cost == 0)
    return {"edge": edge, "side": side, "fix_kind": kind, "cost": cost, **({"policy": policy} if policy else {}),
            **({"resolve": resolve} if resolve else {})}


ADMIN_ACCESS = "arn:aws:iam::aws:policy/AdministratorAccess"
READ_ONLY = "arn:aws:iam::aws:policy/ReadOnlyAccess"


def posture(rule, resource, score, severity, defaults=None):
    return {"rule": rule, "resource": resource, "score": score, "severity": severity, "defaults_used": defaults or []}


def decrypt_cut(principal, key, jewel):
    # Under a derived read the cut is the cheaper underlying edge. Phase 6
    # review, round 5: alternative_fix is the cheapest complete cut sharing
    # no edge with the chosen one, RUNS_AS excluded (SCORING.md 4.3); for
    # these paths that is the other underlying edge (the read, 3), cheaper
    # than the IRSA or Pod Identity trust (5 or 7).
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
def classic(entry=API, sa=SA_API, role=ROLE, defaults=None, also_fixes=None):
    cut, alt = decrypt_cut(role, PII_KEY, PII)
    return path_finding("DARB-PATH-001", entry, PII,
                        [f"RUNS_AS {sa}", f"ASSUMES {role}", f"CAN_READ_PLAINTEXT {PII}"],
                        729, "critical", cut, alt, defaults=IRSA_DEFAULTS if defaults is None else defaults,
                        also_fixes=also_fixes, **pii_decrypt_fixes(cut, alt))


# DARB-POST-007: base medium 350, confidence medium 700: 350 x 700 / 1000 = 245, low.
def no_default_deny(ns):
    return posture("DARB-POST-007", ns, 245, "low")


# DARB-POST-006: base medium 350, confidence high: 350, medium.
def rotation_off(key, defaulted=True):
    return posture("DARB-POST-006", key, 350, "medium", [ROTATION_DEFAULT] if defaulted else [])


ABSENT_PII = [{"rule": "DARB-PATH-001", "jewel": PII}, {"rule": "DARB-PATH-002", "jewel": PII}]

E = {}

# 1 - IRSA -> role -> kms:Decrypt on * -> CMK -> PII bucket.
# Cut (fourth Phase 4 review, SCORING.md 4.1): kms:Decrypt on "*" with no
# encryption context is broad: narrow it, identity side, cost 1. The read is
# s3:GetObject on the PII bucket's objects, an explicit grant (revoke, 3), so
# the decrypt is cheaper and no tie rule is needed.
E["01_classic/vulnerable"] = {"derived_from": "13.2 row 1; 13.1",
                              "findings": [classic(),
                                           no_default_deny(NS_PAYMENTS)]}

# Unclassified data stores (DESIGN.md 5, SCORING.md 1.2; added after
# v0.1.0-rc.1). A bucket, a Secrets Manager secret, an SSM SecureString
# parameter or a Kubernetes Secret with no classification is a crown jewel
# of classification `unclassified`, value 400 (as internal). Blast radius
# counts classified jewels only, so a path to it has blast radius 1000
# when the entry reaches no classified jewel; posture rules do not apply
# to it; a declared intended_access pair is not reported. The scan states
# the stores in one coverage note; crown_jewels.unclassified: ignore drops
# them and says so.
RECEIPTS = "arn:aws:s3:::acme-payment-receipts"
UNCLASSIFIED = "Unclassified data stores"


def unclassified_note(*names):
    return {"subject": UNCLASSIFIED, "contains": [
        f"{len(names)} data store{'s have' if len(names) > 1 else ' has'} no classification; treated as `unclassified`",
        "tag them or list them in `crown_jewels.explicit`", *names]}


def ignored_note(*names):
    return {"subject": UNCLASSIFIED, "contains": [
        f"{len(names)} data store{'s have' if len(names) > 1 else ' has'} no classification and "
        f"{'were' if len(names) > 1 else 'was'} not scanned (`crown_jewels.unclassified: ignore`)", *names]}


# Scenario 1 fixed, and 17 fixed: api (public LoadBalancer, 1000) reads the
# receipts bucket, which has no classification: RUNS_AS, ASSUMES,
# CAN_READ_PLAINTEXT, 3 edges (810): likelihood 810; impact unclassified
# 400 x blast radius 1000 (no classified jewel reached) = 400; 810 x 400 =
# 324, medium. The receipts bucket's encryption configuration does not state
# bucket_key_enabled, so the Bucket Key setting is unknown (normalize/
# terraform) and S3's encryption context is either the bucket ARN (with a
# Bucket Key) or the object ARN (without): the role's DecryptReceipts grants
# kms:Decrypt only under StringEquals kms:EncryptionContext:aws:s3:arn = the
# bucket ARN, so it allows under the first and not the second (scenarios
# 2a and 2c). The decrypt needs an unknown allow: unconfirmed, confidence
# low, worst case 324; undecided names the Bucket Key setting and how to
# state it (DESIGN.md 6.2: every unknown is named with what resolves it).
# Cut (SCORING.md 4.1): the decrypt's identity side is DecryptReceipts,
# explicit (Action kms:Decrypt, a context condition naming the bucket's
# ARN): revoke, 3; aws_kms_key.receipts has no policy, so the AWS default
# key policy applies (Principal: the account root, kms:*): broad, narrow,
# key policy, 2. The decrypt costs 2. The read is s3:GetObject on
# "<receipts ARN>/*", explicit: revoke, identity, 3, and the bucket has no
# policy. The derived read is cut at the decrypt (2 < 3), key policy side;
# the other side is the identity revoke. The alternative sharing no edge is
# the read (3), cheaper than the trust (IRSA, :sub exact: revoke, 7; Pod
# Identity, Principal pods.eks.amazonaws.com exact: revoke, 7).
def receipts_path(defaults):
    cut, alt = decrypt_cut(ROLE, RECEIPTS_KEY, RECEIPTS)
    return path_finding("DARB-PATH-001", API, RECEIPTS,
                        [f"RUNS_AS {SA_API}", f"ASSUMES {ROLE}", f"CAN_READ_PLAINTEXT {RECEIPTS}"],
                        324, "medium", cut, alt, confirmed=False, confidence="low", defaults=defaults,
                        undecided=["Bucket Key", "bucket_key_enabled"],
                        fix=[step(cut[0], "resource", "narrow", 2)],
                        other_side=[step(cut[0], "identity", "revoke", 3)],
                        alternative_detail=[step(alt[0], "identity", "revoke", 3)])


E["01_classic/fixed"] = {"derived_from": "13.2 row 1 fixed: reads only the receipts bucket, decrypt scoped by encryption context; "
                                         "the receipts bucket has no classification",
                         "findings": [receipts_path(IRSA_DEFAULTS), rotation_off(RECEIPTS_KEY), no_default_deny(NS_PAYMENTS)],
                         "absent": ABSENT_PII, "notes": [unclassified_note(RECEIPTS)]}

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
            # The receipts bucket has no classification; api, its only
            # reader, reads it as declared: not reported.
            "absent": ABSENT_PII + [{"rule": "DARB-PATH-001", "jewel": RECEIPTS}],
            "intended_access": intended(status), "notes": [unclassified_note(RECEIPTS)]}

# 3 - decrypt on B's key only with another bucket's encryption context: no path.
for v in ("vulnerable", "fixed"):
    E[f"03_ec_other_bucket/{v}"] = {"derived_from": f"13.2 row 3 ({v})",
                                    "findings": [no_default_deny(NS_PAYMENTS)], "absent": ABSENT_PII}

# 4, 5 - wildcard :sub / :aud only: a path from every service account's
# workload. tools/debug runs as tools/default, not exposed (exposure 400):
# likelihood 400 x 810 = 324; 324 x 900 = 291, medium.
# DARB-POST-001: base high 600, confidence high: 600, high.
NS_TOOLS = f"k8s:{PROD}//Namespace/tools"
for n, row in (("04_wildcard_sub", 4), ("05_aud_only", 5)):
    cut, alt = decrypt_cut(ROLE, PII_KEY, PII)
    debug = path_finding("DARB-PATH-001", f"k8s:{PROD}/tools/Deployment/debug", PII,
                         [f"RUNS_AS k8s:{PROD}/tools/ServiceAccount/default", f"ASSUMES {ROLE}", f"CAN_READ_PLAINTEXT {PII}"],
                         291, "medium", cut, alt, defaults=IRSA_DEFAULTS, **pii_decrypt_fixes(cut, alt))
    E[f"{n}/vulnerable"] = {"derived_from": f"13.2 row {row}",
                            "findings": [classic(), debug, posture("DARB-POST-001", ROLE, 600, "high"),
                                         no_default_deny(NS_PAYMENTS), no_default_deny(NS_TOOLS)]}
    E[f"{n}/fixed"] = {"derived_from": f"13.2 row {row} fixed: :sub pinned to payments/api",
                       "findings": [classic(), no_default_deny(NS_PAYMENTS), no_default_deny(NS_TOOLS)],
                       "absent": [{"rule": "DARB-PATH-001", "entry": f"k8s:{PROD}/tools/Deployment/debug", "jewel": PII},
                                  {"rule": "DARB-POST-001", "resource": ROLE}]}

# 4b - added in the Phase 4 review: a service account without annotation
# whose Role may create pods in its namespace mints an sts.amazonaws.com
# token for itself (RUNS_AS[k8s-token], then ASSUMES via the minted token)
# and the wildcard trust accepts it. Phase 6 review: the pod's own token and
# a token minted for its own account are not another identity (DESIGN.md
# 7.2), so the path is DARB-PATH-001 (it was DARB-PATH-002). builder is not exposed (400),
# 3 edges (810): 324; 324 x 900 = 291, medium. The token is mounted by
# default; the OIDC provider is not in the input, so its audience is the
# documented sts.amazonaws.com.
BUILDER = f"k8s:{PROD}/tools/Deployment/builder"
NS_TOOLS_4B = f"k8s:{PROD}//Namespace/tools"
cut, alt = decrypt_cut(ROLE, PII_KEY, PII)
# Phase 6 review, round 6: builder's own token is a revoke (its Role's
# create-pods binding is used on the path): workload, 5; the read (revoke,
# 3) is the cheapest cut sharing no edge with the decrypt.
E["04b_create_pods_wildcard/vulnerable"] = {"derived_from": "13.2 row 4b (Phase 4 review)", "findings": [
    path_finding("DARB-PATH-001", BUILDER, PII,
                 [f"RUNS_AS[k8s-token] k8s:{PROD}/tools/ServiceAccount/builder", f"ASSUMES {ROLE}", f"CAN_READ_PLAINTEXT {PII}"],
                 291, "medium", cut, alt, defaults=[OIDC_DEFAULT, AUTOMOUNT_DEFAULT], **pii_decrypt_fixes(cut, alt)),
    posture("DARB-POST-001", ROLE, 600, "high"),
    posture("DARB-POST-004", BUILDER, 350, "medium", [AUTOMOUNT_DEFAULT]),
    no_default_deny(NS_TOOLS_4B)]}
E["04b_create_pods_wildcard/fixed"] = {"derived_from": "13.2 row 4b fixed: :sub pinned to payments/api", "findings": [
    posture("DARB-POST-004", BUILDER, 350, "medium", [AUTOMOUNT_DEFAULT]), no_default_deny(NS_TOOLS_4B)],
    "absent": [{"rule": "DARB-PATH-001", "entry": BUILDER, "jewel": PII}, {"rule": "DARB-POST-001", "resource": ROLE}]}

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
# Phase 6 review, dominance (DESIGN.md 8): analytics-admin can rewrite its
# own policies (AdministratorAccess), but it already reads the warehouse
# directly, confirmed: that escalation is dominated, no DARB-PATH-002, and
# nothing else for also_fixes to name.
# Phase 6 review, rounds 5-6: the cheapest cut sharing no edge with CHAIN.
# After analytics-admin: its read of the warehouse and its escalation to
# "role with any permission" (iam:PutRolePolicy / AttachRolePolicy on
# itself; the dominated path, which this cut must break too, DESIGN.md 8)
# all come from AdministratorAccess alone. AWS owns it: it cannot be
# narrowed, only detached: identity, revoke, one change breaking all three
# edges, priced at the dearest revoke among them (CAN_ESCALATE, 4). The
# bucket has no policy and admin may rewrite the key policy: no resource
# side. The derived edge names the decrypt (the read and the decrypt cost
# the same). Nothing after the synthetic node is cuttable; admin may pass no
# role to a service, and IAM writes cannot reach another account's role
# (DESIGN.md 7.2, update-trust: same account only). So: detach, 4, against
# the IRSA trust (revoke, 7).
ADMIN_DECRYPT = f"CAN_DECRYPT[for {WAREHOUSE}] {ADMIN} -> {WAREHOUSE_KEY}"
ADMIN_ESCALATE = f"CAN_ESCALATE[iam:modify-policy] {ADMIN} -> {ADMIN}"
E["06_role_chain_cross_account/vulnerable"] = {"derived_from": "13.2 row 6", "findings": [
    path_finding("DARB-PATH-001", API, WAREHOUSE,
                 [f"RUNS_AS {SA_API}", f"ASSUMES {ROLE}", f"ASSUMES {ADMIN}", f"CAN_READ_PLAINTEXT {WAREHOUSE}"],
                 656, "high", [CHAIN], [ADMIN_DECRYPT, ADMIN_ESCALATE], defaults=IRSA_DEFAULTS,
                 fix=[step(CHAIN, "identity", "narrow", 1)],
                 # analytics-admin's trust names Principal arn:aws:iam::111122223333:root,
                 # an account: broad, narrow, trust side, 5.
                 other_side=[step(CHAIN, "trust", "narrow", 5)],
                 alternative_detail=[step(ADMIN_DECRYPT, "identity", "revoke", 4, ADMIN_ACCESS),
                                     step(ADMIN_ESCALATE, "identity", "revoke", 4, ADMIN_ACCESS)]),
    rotation_off(WAREHOUSE_KEY), no_default_deny(NS_PAYMENTS)]}
E["06_role_chain_cross_account/fixed"] = {"derived_from": "13.2 row 6 fixed: AssumeRole scoped to one role in account A",
                                          "findings": [rotation_off(WAREHOUSE_KEY), no_default_deny(NS_PAYMENTS)],
                                          "absent": [{"rule": "DARB-PATH-001", "jewel": WAREHOUSE}]}

# 7 - iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction -> role reading PII.
# 4 edges, exposure 1000: 729 x 900 = 656, high.
PROCESSOR = f"arn:aws:iam::{ACCT}:role/data-processor"
cut, alt = decrypt_cut(PROCESSOR, PII_KEY, PII)
# Phase 6 review, round 5: the cheapest cut sharing no edge with the
# decrypt is the escalation itself: payments-api's iam:PassRole on "*",
# broad: narrow, identity, 2 (data-processor's trust names
# lambda.amazonaws.com exactly: revoke, trust, 7); the read costs 3.
PASS = f"CAN_ESCALATE[iam:passrole:lambda] {ROLE} -> {PROCESSOR}"
E["07_passrole_lambda/vulnerable"] = {"derived_from": "13.2 row 7", "findings": [
    path_finding("DARB-PATH-002", API, PII,
                 [f"RUNS_AS {SA_API}", f"ASSUMES {ROLE}", f"CAN_ESCALATE {PROCESSOR}", f"CAN_READ_PLAINTEXT {PII}"],
                 656, "high", cut, [PASS], defaults=IRSA_DEFAULTS,
                 **{**pii_decrypt_fixes(cut, alt), "alternative_detail": [step(PASS, "identity", "narrow", 2)]}),
    no_default_deny(NS_PAYMENTS)]}
E["07_passrole_lambda/fixed"] = {"derived_from": "13.2 row 7 fixed: PassRole scoped and conditioned, no InvokeFunction",
                                 "findings": [no_default_deny(NS_PAYMENTS)], "absent": ABSENT_PII}

# 8 - RBAC create pods in payments; SA api there has an IRSA role reading PII.
# ci-runner (not exposed, 400) uses its mounted token (automount: default true),
# creates a pod as api, which assumes the role: 4 edges (729):
# 400 x 729 = 291; 291 x 900 = 261, medium.
# The api workload's own read of PII (scenario 1 shape, 729) is in both variants.
# DARB-POST-004 on ci-runner: base medium 350, confidence high: 350, medium.
CI = f"k8s:{PROD}/payments/Deployment/ci-runner"
SA_CI = f"k8s:{PROD}/payments/ServiceAccount/ci"
cut, alt = decrypt_cut(ROLE, PII_KEY, PII)
# Phase 6 review: the cut of both findings is the same edge (the role's
# broad kms:Decrypt for PII): each also fixes the other. Round 6: for ci,
# the cheapest cut sharing no edge with it is the read (revoke, 3); ci's
# own token (revoke, its binding is used: 5) and the create-pods binding
# (5) are dearer.
E["08_rbac_create_pods/vulnerable"] = {"derived_from": "13.2 row 8", "findings": [
    classic(also_fixes=[{"rule": "DARB-PATH-002", "entry": CI, "jewel": PII}]),
    path_finding("DARB-PATH-002", CI, PII,
                 [f"RUNS_AS[k8s-token] {SA_CI}", f"CAN_ESCALATE {SA_API}", f"ASSUMES {ROLE}", f"CAN_READ_PLAINTEXT {PII}"],
                 261, "medium", cut, alt, defaults=IRSA_DEFAULTS + [AUTOMOUNT_DEFAULT],
                 also_fixes=[{"rule": "DARB-PATH-001", "entry": API, "jewel": PII}], **pii_decrypt_fixes(cut, alt)),
    posture("DARB-POST-004", CI, 350, "medium", [AUTOMOUNT_DEFAULT]),
    no_default_deny(NS_PAYMENTS)]}
E["08_rbac_create_pods/fixed"] = {"derived_from": "13.2 row 8 fixed: get/list/watch only", "findings": [
    classic(), posture("DARB-POST-004", CI, 350, "medium", [AUTOMOUNT_DEFAULT]), no_default_deny(NS_PAYMENTS)],
    "absent": [{"rule": "DARB-PATH-002", "entry": CI, "jewel": PII}]}

# 9 - hostNetwork DaemonSet + IMDSv1 -> node role -> s3:GetObject on * -> SSE-S3 PII.
# Not exposed (400), 2 edges (900), NODE_ROLE precondition known satisfied (900):
# 400 x 900 = 360; 360 x 900 = 324; x confidence 1000 = 324; 324 x 900 = 291, medium.
# The bucket states no encryption: SSE-S3 by documented default.
# DARB-POST-002: base high 600: high.
NODE = f"arn:aws:iam::{ACCT}:role/eks-node"
EXPORTS = "arn:aws:s3:::acme-customer-exports"
NS_MON = f"k8s:{PROD}//Namespace/monitoring"
IMDS_EDGE = f"NODE_ROLE k8s:{PROD}/monitoring/DaemonSet/node-monitor -> {NODE}"
E["09_hostnetwork_imds/vulnerable"] = {"derived_from": "13.2 row 9", "findings": [
    path_finding("DARB-PATH-001", f"k8s:{PROD}/monitoring/DaemonSet/node-monitor", EXPORTS,
                 [f"NODE_ROLE {NODE}", f"CAN_READ_PLAINTEXT {EXPORTS}"], 291, "medium",
                 [f"CAN_READ {NODE} -> {EXPORTS}"], [IMDS_EDGE], defaults=[S3_DEFAULT],
                 # The node role grants s3:GetObject on "*": broad, narrow, identity, 1.
                 # The exports bucket has no policy and no KMS key: no other side.
                 # Round 5: the only other edge is NODE_ROLE; the pod uses the host
                 # network, so the hop limit does not stop it and the node group's
                 # nodes do not keep pods out (hop limit 2): the endpoint off, node,
                 # revoke, 5 (SCORING.md 4.1).
                 fix=[step(f"CAN_READ {NODE} -> {EXPORTS}", "identity", "narrow", 1)], other_side=[],
                 alternative_detail=[step(IMDS_EDGE, "node", "revoke", 5)]),
    posture("DARB-POST-002", f"eks-nodegroup:{PROD}/default", 600, "high"),
    no_default_deny(NS_MON)]}
E["09_hostnetwork_imds/fixed"] = {"derived_from": "13.2 row 9 fixed: IMDSv2 required, hop limit 1, no hostNetwork",
                                  "findings": [no_default_deny(NS_MON)],
                                  "absent": [{"rule": "DARB-PATH-001", "jewel": EXPORTS},
                                             {"rule": "DARB-POST-002", "resource": f"eks-nodegroup:{PROD}/default"}]}

# 10 - decrypt only from a key policy with aws:PrincipalOrgID, org not configured:
# UNKNOWN, and it needs an unknown allow (the key policy's condition):
# unconfirmed, confidence low. Phase 6 review: the score is the worst case,
# the org ID matching: 1000 x 810 = 810; 810 x 900 = 729, critical (it was
# 291, medium, when confidence was a factor).
# Cut: the role has no kms:Decrypt of its own; the key policy grants it to
# Principal "*" only under aws:PrincipalOrgID, which is unknown (no
# organization configured): the side rests only on an unknown Allow, so its
# fix is resolve, 0, assume: {"aws:PrincipalOrgID": [...]} in darb.yaml
# (Phase 6 review, round 7; it was narrow, key policy, 2): no patch, as in
# Phase 5. The alternative is the read, an explicit s3:GetObject on the
# bucket's objects: revoke, identity side, 3.
SHARED_KEY = f"arn:aws:kms:us-east-1:{ACCT}:key/tf-aws_kms_key.shared"
ORG_ASSUME = 'assume: {"aws:PrincipalOrgID": [...]} in darb.yaml'
cut, alt = decrypt_cut(ROLE, SHARED_KEY, PII)
E["10_kms_principal_org_id/vulnerable"] = {"derived_from": "13.2 row 10 (no organization ID configured)", "findings": [
    path_finding("DARB-PATH-001", API, PII, [f"RUNS_AS {SA_API}", f"ASSUMES {ROLE}", f"CAN_READ_PLAINTEXT {PII}"],
                 729, "critical", cut, alt, confirmed=False, confidence="low", defaults=IRSA_DEFAULTS,
                 undecided=["aws:PrincipalOrgID"],
                 fix=[step(cut[0], "resource", "resolve", 0, resolve=ORG_ASSUME)], other_side=[],
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
# DARB-POST-005: base high 600: high.
LEADS = "arn:aws:s3:::acme-marketing-leads"
E["12_public_bucket/vulnerable"] = {"derived_from": "13.2 row 12", "findings": [
    path_finding("DARB-PATH-003", "anonymous", LEADS, [f"CAN_READ_PLAINTEXT {LEADS}"], 900, "critical",
                 [f"CAN_READ anonymous -> {LEADS}"], defaults=[S3_DEFAULT],
                 # The bucket policy grants Principal "*": broad, narrow, bucket policy, 2.
                 # The anonymous caller has no identity policy: no other side.
                 # Round 5: the path is that one edge: no other cut, no alternative.
                 fix=[step(f"CAN_READ anonymous -> {LEADS}", "resource", "narrow", 2)], other_side=[], alternative_detail=[]),
    posture("DARB-POST-005", LEADS, 600, "high")]}
# 12/account_block (DESIGN.md 12.1 priority 2; Phase 7): the vulnerable
# variant plus aws_s3_account_public_access_block with
# restrict_public_buckets = true. S3 applies the most restrictive of the
# account and bucket settings (S3 User Guide, Blocking public access: "If
# the block public access settings for the access point, bucket, or account
# differ, then Amazon S3 applies the most restrictive combination of the
# access point, bucket, and account settings."), and RestrictPublicBuckets
# limits a bucket with a public policy to AWS service principals and the
# owner account's authorized users: the anonymous read is denied, no
# CAN_READ edge, no DARB-PATH-003; the bucket is effectively blocked, no
# DARB-POST-005. The policy still grants s3:GetObject to "*" with no
# condition, and the anonymous caller is an entry point, so DARB-POST-008
# stays as in the vulnerable variant: 600, high (added with BROAD below).
E["12_public_bucket/account_block"] = {"derived_from": "DESIGN.md 12.1 priority 2: account-level Block Public Access on",
                                       "findings": [], "absent": [{"rule": "DARB-PATH-003", "jewel": LEADS},
                                                                  {"rule": "DARB-POST-005", "resource": LEADS}]}
E["12_public_bucket/fixed"] = {"derived_from": "13.2 row 12 fixed: Block Public Access on, policy names one role",
                               "findings": [], "absent": [{"rule": "DARB-PATH-003", "jewel": LEADS},
                                                          {"rule": "DARB-POST-005", "resource": LEADS}]}

# 13 - module + for_each -> 3 IRSA roles for 3 SAs, SSE-S3 PII bucket.
# Plan: CronJobs are not exposed (400), 3 edges (810): 400 x 810 = 324;
# 324 x 900 = 291, medium; cut CAN_READ (no decrypt under SSE-S3).
# Static: role names unresolved -> UNKNOWN that needs an unknown allow,
# unconfirmed, confidence low. Phase 6 review: worst case 324 x 900 = 291,
# medium (it was 116, low); exit 3 at default tolerance (the unconfirmed
# findings are below the default --fail-on high).
NS_ANALYTICS = f"k8s:{PROD}//Namespace/analytics"
def reader(name, static=False):
    role = f"arn:aws:iam::{ACCT}:role/reader-" + ("${darb:unresolved:each.value}" if static else name)
    trust = f"ASSUMES k8s:{PROD}/analytics/ServiceAccount/{name} -> {role}"
    if static:
        # Round 7: statically the trust's :sub (...:analytics:${each.value})
        # and the read's Resource (${var.bucket}/*) are unresolved: each edge
        # rests only on an unknown Allow, so each is resolved (0, --plan).
        # Equal cuts, one command each (--plan): closest to the entry, the
        # trust. A cut with a resolve step takes an alternative of known
        # steps only; the read is a resolve step too and RUNS_AS is never
        # offered: alternative_fix [] (SCORING.md 4.3).
        return path_finding("DARB-PATH-001", f"k8s:{PROD}/analytics/CronJob/{name}", PII,
                            [f"RUNS_AS k8s:{PROD}/analytics/ServiceAccount/{name}", f"ASSUMES {role}", f"CAN_READ_PLAINTEXT {PII}"],
                            291, "medium", [trust], [],
                            confirmed=False, confidence="low", defaults=IRSA_DEFAULTS,
                            fix=[step(trust, "trust", "resolve", 0, resolve="--plan")], other_side=[],
                            alternative_detail=[])
    return path_finding("DARB-PATH-001", f"k8s:{PROD}/analytics/CronJob/{name}", PII,
                        [f"RUNS_AS k8s:{PROD}/analytics/ServiceAccount/{name}", f"ASSUMES {role}", f"CAN_READ_PLAINTEXT {PII}"],
                        291, "medium", [f"CAN_READ {role} -> {PII}"], [trust],
                        confirmed=not static, confidence="low" if static else "high", defaults=IRSA_DEFAULTS,
                        # s3:GetObject on "arn:aws:s3:::${var.bucket}/*": the plan resolves it
                        # to the PII bucket's objects, explicit; statically var.bucket is
                        # unresolved, which cannot be shown broad (SCORING.md 4.1). Either
                        # way: revoke, identity, 3. SSE-S3 and no bucket policy: nothing else.
                        fix=[step(f"CAN_READ {role} -> {PII}", "identity", "revoke", 3)], other_side=[],
                        # Round 5: the only other cuttable edge is the IRSA trust; its :sub is
                        # system:serviceaccount:analytics:${each.value}, exact in the plan and
                        # unresolved statically (counts as explicit): revoke, trust, 7.
                        alternative_detail=[step(trust, "trust", "revoke", 7)])
READERS = ("etl", "bi", "ml")
E["13_module_for_each/vulnerable"] = {"derived_from": "13.2 row 13 (plan mode)",
                                      "findings": [reader(n) for n in READERS] + [no_default_deny(NS_ANALYTICS)]}
E["13_module_for_each/fixed"] = {"derived_from": "13.2 row 13 fixed (plan mode): roles read a non-PII bucket",
                                 "findings": [no_default_deny(NS_ANALYTICS)],
                                 "absent": [{"rule": "DARB-PATH-001", "jewel": PII}]}
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
    trust = f"ASSUMES k8s:{PROD}/apps/ServiceAccount/{sa} -> {role}"
    return path_finding("DARB-PATH-001", f"k8s:{PROD}/apps/Deployment/{sa}", bucket,
                        [f"RUNS_AS k8s:{PROD}/apps/ServiceAccount/{sa}", f"ASSUMES {role}", f"CAN_READ_PLAINTEXT {bucket}"],
                        291, "medium", [f"CAN_READ {role} -> {bucket}"], [trust], defaults=IRSA_DEFAULTS,
                        # The inline policy "data" grants s3:GetObject on "arn:aws:s3:::data-<acct>/*":
                        # explicit, revoke, identity, 3. SSE-S3, no bucket policy: nothing else.
                        # Round 5: the IRSA trust's :sub is system:serviceaccount:apps:<sa>
                        # exactly: revoke, trust, 7.
                        fix=[step(f"CAN_READ {role} -> {bucket}", "identity", "revoke", 3)], other_side=[],
                        alternative_detail=[step(trust, "trust", "revoke", 7)])
NO_CROSSING = [
    {"from": f"arn:aws:iam::{ACCT}:role/app", "to": f"arn:aws:s3:::data-{B}"},
    {"from": f"arn:aws:iam::{B}:role/app", "to": f"arn:aws:s3:::data-{ACCT}"},
    {"from": f"k8s:{PROD}/apps/ServiceAccount/app-a", "to": f"arn:aws:iam::{B}:role/app"},
    {"from": f"k8s:{PROD}/apps/ServiceAccount/app-b", "to": f"arn:aws:iam::{ACCT}:role/app"},
]
CROSS_ABSENT = [
    {"rule": "DARB-PATH-001", "entry": f"k8s:{PROD}/apps/Deployment/app-a", "jewel": f"arn:aws:s3:::data-{B}"},
    {"rule": "DARB-PATH-001", "entry": f"k8s:{PROD}/apps/Deployment/app-b", "jewel": f"arn:aws:s3:::data-{ACCT}"},
]
NS_APPS = f"k8s:{PROD}//Namespace/apps"
E["14_same_names_two_accounts/vulnerable"] = {"derived_from": "13.2 row 14 (entries added in the Phase 4 review)", "distinct_fingerprints": True,
                                              "findings": [own(ACCT, "app-a"), own(B, "app-b"), no_default_deny(NS_APPS)],
                                              "absent": CROSS_ABSENT, "no_edges": NO_CROSSING}
E["14_same_names_two_accounts/fixed"] = {"derived_from": "13.2 row 14 fixed: account 444455556666's role can only list",
                                         "findings": [own(ACCT, "app-a"), no_default_deny(NS_APPS)],
                                         "absent": CROSS_ABSENT + [{"rule": "DARB-PATH-001", "jewel": f"arn:aws:s3:::data-{B}"}],
                                         "no_edges": NO_CROSSING}

# 18 - two clusters named prod in one account, in eu-west-1 and us-east-1
# (Phase 6: cluster identity by ARN). Each has the service account apps/app,
# annotated with a different role: app-eu trusts the eu-west-1 cluster's
# OIDC issuer, app-us the us-east-1 one, each for
# system:serviceaccount:apps:app; each role reads its own region's SSE-S3
# PII bucket. The two clusters' objects have different identities (their
# keys are their ARNs), so: two paths, nothing crossing between the
# clusters, and no coverage gap (exit 0: both paths are medium, below
# --fail-on high). Same arithmetic as scenario 14: not exposed (400), 3
# edges (810): 324; x 900 = 291, medium; the cut is the explicit read
# (revoke, identity, 3); IRSA relies on the documented audience defaults.
EUW1 = f"arn:aws:eks:eu-west-1:{ACCT}:cluster/prod"
USE1 = f"arn:aws:eks:us-east-1:{ACCT}:cluster/prod"


def regional(cluster, region):
    role, bucket = f"arn:aws:iam::{ACCT}:role/app-{region}", f"arn:aws:s3:::data-{region}"
    trust = f"ASSUMES k8s:{cluster}/apps/ServiceAccount/app -> {role}"
    return path_finding("DARB-PATH-001", f"k8s:{cluster}/apps/Deployment/app", bucket,
                        [f"RUNS_AS k8s:{cluster}/apps/ServiceAccount/app", f"ASSUMES {role}", f"CAN_READ_PLAINTEXT {bucket}"],
                        291, "medium", [f"CAN_READ {role} -> {bucket}"], [trust], defaults=IRSA_DEFAULTS,
                        # The inline policy grants s3:GetObject on "arn:aws:s3:::data-<region>/*":
                        # explicit, revoke, identity, 3. SSE-S3, no bucket policy: nothing else.
                        # Round 5: each role's trust pins system:serviceaccount:apps:app on
                        # its own cluster's issuer: revoke, trust, 7.
                        fix=[step(f"CAN_READ {role} -> {bucket}", "identity", "revoke", 3)], other_side=[],
                        alternative_detail=[step(trust, "trust", "revoke", 7)])


TWO_PROD_NO_CROSSING = [
    {"from": f"k8s:{EUW1}/apps/ServiceAccount/app", "to": f"arn:aws:iam::{ACCT}:role/app-us"},
    {"from": f"k8s:{USE1}/apps/ServiceAccount/app", "to": f"arn:aws:iam::{ACCT}:role/app-eu"},
    {"from": f"arn:aws:iam::{ACCT}:role/app-eu", "to": "arn:aws:s3:::data-us"},
    {"from": f"arn:aws:iam::{ACCT}:role/app-us", "to": "arn:aws:s3:::data-eu"},
]
TWO_PROD_CROSS_ABSENT = [
    {"rule": "DARB-PATH-001", "entry": f"k8s:{EUW1}/apps/Deployment/app", "jewel": "arn:aws:s3:::data-us"},
    {"rule": "DARB-PATH-001", "entry": f"k8s:{USE1}/apps/Deployment/app", "jewel": "arn:aws:s3:::data-eu"},
]
TWO_PROD_NS = [no_default_deny(f"k8s:{EUW1}//Namespace/apps"), no_default_deny(f"k8s:{USE1}//Namespace/apps")]
E["18_same_cluster_name_two_regions/vulnerable"] = {
    "derived_from": "Phase 6 instruction: two clusters named prod in two regions", "distinct_fingerprints": True, "exit_code": 0,
    "findings": [regional(EUW1, "eu"), regional(USE1, "us")] + TWO_PROD_NS,
    "absent": TWO_PROD_CROSS_ABSENT, "no_edges": TWO_PROD_NO_CROSSING}
E["18_same_cluster_name_two_regions/fixed"] = {
    "derived_from": "Phase 6 instruction, fixed: the us-east-1 role can only list its bucket", "exit_code": 0,
    "findings": [regional(EUW1, "eu")] + TWO_PROD_NS,
    "absent": TWO_PROD_CROSS_ABSENT + [{"rule": "DARB-PATH-001", "jewel": "arn:aws:s3:::data-us"}],
    "no_edges": TWO_PROD_NO_CROSSING}

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
                                      "findings": [receipts_path(POD_IDENTITY_DEFAULTS), rotation_off(RECEIPTS_KEY), no_default_deny(NS_PAYMENTS)],
                                      "absent": ABSENT_PII, "notes": [unclassified_note(RECEIPTS)]}


# DARB-POST-008 (Phase 5 review): a broad grant of a sensitive action.
# Derived by hand from each fixture's policies, before the rule existed:
# an Allow of kms:Decrypt, sts:AssumeRole, iam:PassRole, s3:GetObject,
# secretsmanager:GetSecretValue or ssm:GetParameter (or a wildcard covering
# one) on every resource ("*"), with no condition or only organization /
# account conditions, that the principal's permissions boundary does not
# take away; or a resource policy granting one to Principal "*" under the
# same conditions. One finding per principal or resource: base high 600,
# confidence high: 600, high.
def broad_grant(resource, reachable=True):
    # Phase 5 follow-up: graded by reachability. High (600) when an entry
    # point reaches the principal holding the grant (a workload directly,
    # IRSA, Pod Identity, CAN_ESCALATE, an ASSUMES chain; for a grant to
    # every principal, any reached principal, or the anonymous caller when
    # it has no condition); medium (base 350, confidence high: 350) when no
    # path reaches it: real accounts hold intended admin roles.
    return posture("DARB-POST-008", resource, 600 if reachable else 350, "high" if reachable else "medium")


ADMIN_ROLE = "arn:aws:iam::444455556666:role/analytics-admin"
BROAD = {
    "01_classic/vulnerable": [ROLE],                          # kms:Decrypt on "*"
    "06_role_chain_cross_account/vulnerable": [ROLE, ADMIN_ROLE],  # sts:AssumeRole on "*"; AdministratorAccess
    # AdministratorAccess stays, but payments-api may assume only
    # role/reporting (not in the input): no entry reaches the admin: medium.
    "06_role_chain_cross_account/fixed": [(ADMIN_ROLE, False)],
    "07_passrole_lambda/vulnerable": [ROLE],                  # iam:PassRole on "*"
    "09_hostnetwork_imds/vulnerable": [NODE],                 # s3:GetObject on "*"
    # The fixed variant fixes IMDS only: IMDSv2, hop limit 1, no hostNetwork
    # leave no NODE_ROLE edge, so no entry reaches the node role: medium.
    "09_hostnetwork_imds/fixed": [(NODE, False)],
    "10_kms_principal_org_id/vulnerable": [SHARED_KEY],       # key policy: Principal "*", org condition only
    "11_boundary_deny/vulnerable": [ROLE],                    # boundary allows everything else
    "12_public_bucket/vulnerable": [LEADS],                   # bucket policy: Principal "*"
    "12_public_bucket/account_block": [LEADS],                # the same policy; the account block does not change it
    "16_malformed_inputs/vulnerable": [ROLE],                 # kms:Decrypt on "*"
    "16_malformed_inputs/fixed": [ROLE],                      # same role file
    "17_pod_identity_classic/vulnerable": [ROLE],             # kms:Decrypt on "*"
}
# 11 fixed: kms:Decrypt on "*" is written, but the boundary allows only
# sqs:* and logs:*, so the grant has no effect: no finding.
for variant, resources in BROAD.items():
    E[variant]["findings"] += [broad_grant(*r) if isinstance(r, tuple) else broad_grant(r) for r in resources]


# 19-21 - secrets as targets (Phase 6, DESIGN.md 7.3). Written before the
# engine read any of them.
#
# 19 - Secrets Manager. payments/api (public LoadBalancer, IRSA, as in
# scenario 1) reads the secret prod/db (DataClass secret) through
# secretsmanager:GetSecretValue on its exact ARN, and decrypts with
# kms:Decrypt on "*" (no encryption-context condition) under a customer
# managed key whose key policy is the default (the account root, kms:*).
# Exposure 1000, 3 edges (810): likelihood 810; secret 1000 x blast radius
# 1000 = 1000: 810, critical. The cut is the decrypt, broad: narrow,
# identity, 1; the key policy is broad too: narrow, resource side, 2; the
# alternative is the read, an explicit grant: revoke, identity, 3 (the
# secret has no resource policy: no other side). DARB-POST-008 on the
# role (kms:Decrypt on "*", reached from api): 600, high.
SECRET = f"arn:aws:secretsmanager:us-east-1:{ACCT}:secret:prod/db-aaaaaa"
SECRET_KEY = f"arn:aws:kms:us-east-1:{ACCT}:key/11111111-2222-3333-4444-555555555555"
# 20 - SSM SecureString: the same shape, ssm:GetParameter on the
# parameter's exact ARN, kms:Decrypt on "*" under a customer managed key.
PARAM = f"arn:aws:ssm:us-east-1:{ACCT}:parameter/prod/db/password"
PARAM_KEY = f"arn:aws:kms:us-east-1:{ACCT}:key/66666666-7777-8888-9999-000000000000"


def secret_target(jewel, key):
    cut, alt = decrypt_cut(ROLE, key, jewel)
    return path_finding("DARB-PATH-001", API, jewel,
                        [f"RUNS_AS {SA_API}", f"ASSUMES {ROLE}", f"CAN_READ_PLAINTEXT {jewel}"],
                        810, "critical", cut, alt, defaults=IRSA_DEFAULTS, **pii_decrypt_fixes(cut, alt))


for n, jewel, key, other in (
        ("19_secrets_manager", SECRET, SECRET_KEY, "the decrypt is conditioned on another secret's SecretARN encryption context"),
        ("20_ssm_securestring", PARAM, PARAM_KEY, "the decrypt is conditioned on another parameter's PARAMETER_ARN encryption context")):
    E[f"{n}/vulnerable"] = {"derived_from": "Phase 6 instruction: " + n.split("_", 1)[1].replace("_", " ") + " as a target",
                            "findings": [secret_target(jewel, key), broad_grant(ROLE), no_default_deny(NS_PAYMENTS)]}
    E[f"{n}/fixed"] = {"derived_from": "Phase 6 instruction, fixed: " + other,
                       "findings": [no_default_deny(NS_PAYMENTS)],
                       "absent": [{"rule": "DARB-PATH-001", "jewel": jewel}, {"rule": "DARB-POST-008", "resource": ROLE}]}

# 21 - Kubernetes Secret. ci-runner (not exposed: 400) runs as ci, whose
# Role may get secrets in payments; its token is mounted by default. The
# path is its own Kubernetes token (RUNS_AS[k8s-token], DESIGN.md 7.2:
# direct access, Phase 6 review), then the RBAC read of
# payments/db-credentials (DataClass secret, 1000): DARB-PATH-001. 2 edges (900): 400 x 900 = 360; x 1000 = 360, medium.
# The cut is turning the token mount off: ci's Role binding is used on the
# path, so it takes away a right granted on purpose: workload, revoke, 5
# (Phase 6 review, round 6; it was narrow, 3). The RBAC read also costs 5
# (rbac, revoke): equal, closest to the entry: the token; the read is the
# alternative. DARB-POST-004 on ci-runner (token mounted by default, the
# account has RBAC): 350, medium. Fixed: the pod sets
# automountServiceAccountToken: false: no path, no DARB-POST-004.
K8S_SECRET = f"k8s:{PROD}/payments/Secret/db-credentials"
TOKEN_EDGE = f"RUNS_AS[k8s-token] {CI} -> {SA_CI}"
K8S_READ = f"CAN_READ_PLAINTEXT {SA_CI} -> {K8S_SECRET}"
E["21_k8s_secret/vulnerable"] = {"derived_from": "Phase 6 instruction: Kubernetes Secrets as targets", "findings": [
    path_finding("DARB-PATH-001", CI, K8S_SECRET, [f"RUNS_AS[k8s-token] {SA_CI}", f"CAN_READ_PLAINTEXT {K8S_SECRET}"],
                 360, "medium", [TOKEN_EDGE], [K8S_READ], defaults=[AUTOMOUNT_DEFAULT],
                 fix=[step(TOKEN_EDGE, "workload", "revoke", 5)],
                 # The cut edge (a fact) has no other side. Round 5: the only
                 # other edge is the RBAC read itself: rbac, revoke, 5.
                 other_side=[], alternative_detail=[step(K8S_READ, "rbac", "revoke", 5)]),
    posture("DARB-POST-004", CI, 350, "medium", [AUTOMOUNT_DEFAULT]),
    no_default_deny(NS_PAYMENTS)]}
E["21_k8s_secret/fixed"] = {"derived_from": "Phase 6 instruction, fixed: automountServiceAccountToken: false",
                            "findings": [no_default_deny(NS_PAYMENTS)],
                            "absent": [{"rule": "DARB-PATH-001", "jewel": K8S_SECRET}, {"rule": "DARB-POST-004", "resource": CI}]}

# 23 - Kubernetes Secrets read without RBAC (DESIGN.md 12.1, priority 1;
# Phase 7). The kubelet gives a pod every Secret its spec names (a volume,
# env valueFrom.secretKeyRef, envFrom.secretRef), with no RBAC check on
# the pod's identity (Kubernetes docs, Secrets, sections "Using Secrets as
# files from a Pod" and "Using Secrets as environment variables"); and
# whoever may create pods in a namespace can create one that mounts any
# Secret of it (Kubernetes docs, RBAC Good Practices, section "Workload
# creation": permission to create workloads in a namespace implicitly
# grants access to the Secrets that can be mounted in its pods).
# Vulnerable: api (not exposed: 400) names payments/db-credentials
# (DataClass secret, 1000) in an env var and a volume; its token is not
# mounted, it has no RBAC. One edge, CAN_READ_PLAINTEXT[mount]: 400 x 1000
# (1 edge) = 400; x 1000 = 400, medium. The only fix is the workload's:
# stop naming the Secret, revoke (it removes what the pod was written to
# use), 5. No other side, no alternative (one edge).
# ci-runner (400) runs as ci, token mounted by default, whose Role may
# create pods in payments: RUNS_AS[k8s-token], then
# CAN_READ_PLAINTEXT[pod-create] (an RBAC right, like the [k8s] read of
# scenario 21). 2 edges: 360, medium. Cut as in scenario 21: the token
# mount (workload, revoke, 5, the path uses ci's RBAC) and the Role grant
# (rbac, revoke, 5) are equal: closest to the entry, the token; the grant
# is the alternative. ci may also create pods running as api
# (CAN_ESCALATE[rbac] ci -> api), but nothing leads from api's account to
# the Secret (the mount edge starts at the api workload): no escalation
# finding. DARB-POST-004 on ci-runner (350, medium, the default), and
# DARB-POST-007 on payments. Fixed: api names only api-config (no
# DataClass: not a jewel), ci's Role is get/list pods: no path;
# DARB-POST-004 stays (ci still has RBAC, token mounted by default).
API_W = f"k8s:{PROD}/payments/Deployment/api"
DB_SECRET = f"k8s:{PROD}/payments/Secret/db-credentials"
MOUNT_EDGE = f"CAN_READ_PLAINTEXT[mount] {API_W} -> {DB_SECRET}"
POD_CREATE_EDGE = f"CAN_READ_PLAINTEXT[pod-create] {SA_CI} -> {DB_SECRET}"
E["23_k8s_secret_mount/vulnerable"] = {"derived_from": "DESIGN.md 12.1 priority 1: Secrets mounted into pods, and through pod creation", "findings": [
    path_finding("DARB-PATH-001", API_W, DB_SECRET, [f"CAN_READ_PLAINTEXT[mount] {DB_SECRET}"],
                 400, "medium", [MOUNT_EDGE], [], fix=[step(MOUNT_EDGE, "workload", "revoke", 5)],
                 other_side=[], alternative_detail=[]),
    path_finding("DARB-PATH-001", CI, DB_SECRET, [f"RUNS_AS[k8s-token] {SA_CI}", f"CAN_READ_PLAINTEXT[pod-create] {DB_SECRET}"],
                 360, "medium", [TOKEN_EDGE], [POD_CREATE_EDGE], defaults=[AUTOMOUNT_DEFAULT],
                 fix=[step(TOKEN_EDGE, "workload", "revoke", 5)],
                 other_side=[], alternative_detail=[step(POD_CREATE_EDGE, "rbac", "revoke", 5)]),
    posture("DARB-POST-004", CI, 350, "medium", [AUTOMOUNT_DEFAULT]),
    no_default_deny(NS_PAYMENTS)]}
# Fixed, with unclassified stores: api-config has no classification, so it
# is a jewel of classification unclassified. api (not exposed: 400) names
# it: one edge, CAN_READ_PLAINTEXT[mount]: likelihood 400; impact 400 x
# blast radius 1000 = 400; 400 x 400 = 160, low. Cut as in the vulnerable
# variant: stop naming it, workload, revoke, 5; one edge, no alternative.
# ci's Role may only get and list pods: it reaches neither Secret.
API_CONFIG = f"k8s:{PROD}/payments/Secret/api-config"
CONFIG_MOUNT = f"CAN_READ_PLAINTEXT[mount] {API_W} -> {API_CONFIG}"
E["23_k8s_secret_mount/fixed"] = {"derived_from": "DESIGN.md 12.1 priority 1, fixed: no classified jewel named, no pod creation",
                                  "findings": [
                                      path_finding("DARB-PATH-001", API_W, API_CONFIG, [f"CAN_READ_PLAINTEXT[mount] {API_CONFIG}"],
                                                   160, "low", [CONFIG_MOUNT], [], fix=[step(CONFIG_MOUNT, "workload", "revoke", 5)],
                                                   other_side=[], alternative_detail=[]),
                                      posture("DARB-POST-004", CI, 350, "medium", [AUTOMOUNT_DEFAULT]), no_default_deny(NS_PAYMENTS)],
                                  "absent": [{"rule": "DARB-PATH-001", "jewel": DB_SECRET}],
                                  "notes": [unclassified_note(API_CONFIG)]}

# 24 - an untagged bucket (added after v0.1.0-rc.1). records/exporter (no
# Service: not exposed, 400) runs as records/exporter, whose IRSA role
# records-exporter (trust: :sub and :aud exact) has s3:GetObject on
# "arn:aws:s3:::patient-records-vault/*". The bucket has no tags, no
# policy and no encryption configuration (SSE-S3 by documented default):
# unclassified. Its public access block turns everything off: with no
# bucket policy nothing grants public access (ACLs are not modelled yet, a
# note), so it adds no edge. RUNS_AS, ASSUMES,
# CAN_READ_PLAINTEXT: 3 edges (810): 400 x 810 = 324; impact 400 x blast
# radius 1000 = 400; 324 x 400 = 129 (rounded down), low. Cut: the read,
# explicit: revoke, identity, 3; no bucket policy, no key: no other side.
# Alternative: the IRSA trust, :sub exact: revoke, trust, 7 (RUNS_AS is
# never offered). Posture rules do not apply to an unclassified bucket:
# no DARB-POST-005, although restrict_public_buckets is false (it would
# fire on a classified bucket); DARB-POST-007 on records. The coverage note names the bucket.
# fixed: the exporter only writes to the vault (s3:PutObject): no read, no
# path; the bucket is still unclassified, so the note stays.
# ignore: the vulnerable input with crown_jewels.unclassified: ignore in
# darb.yaml: the bucket is no jewel, no path, and the note says the
# store was not scanned.
VAULT = "arn:aws:s3:::patient-records-vault"
EXPORTER = f"k8s:{PROD}/records/Deployment/exporter"
SA_EXPORTER = f"k8s:{PROD}/records/ServiceAccount/exporter"
EXPORTER_ROLE = f"arn:aws:iam::{ACCT}:role/records-exporter"
NS_RECORDS = f"k8s:{PROD}//Namespace/records"
VAULT_READ = f"CAN_READ {EXPORTER_ROLE} -> {VAULT}"
EXPORTER_TRUST = f"ASSUMES {SA_EXPORTER} -> {EXPORTER_ROLE}"
E["24_unclassified_bucket/vulnerable"] = {"derived_from": "after v0.1.0-rc.1: a data store without classification is a crown jewel, unclassified", "findings": [
    path_finding("DARB-PATH-001", EXPORTER, VAULT,
                 [f"RUNS_AS {SA_EXPORTER}", f"ASSUMES {EXPORTER_ROLE}", f"CAN_READ_PLAINTEXT {VAULT}"],
                 129, "low", [VAULT_READ], [EXPORTER_TRUST], defaults=IRSA_DEFAULTS + [S3_DEFAULT],
                 fix=[step(VAULT_READ, "identity", "revoke", 3)], other_side=[],
                 alternative_detail=[step(EXPORTER_TRUST, "trust", "revoke", 7)]),
    no_default_deny(NS_RECORDS)],
    "absent": [{"rule": "DARB-POST-005", "resource": VAULT}],
    "notes": [unclassified_note(VAULT)]}
E["24_unclassified_bucket/fixed"] = {"derived_from": "after v0.1.0-rc.1, fixed: the exporter only writes to the bucket",
                                     "findings": [no_default_deny(NS_RECORDS)],
                                     "absent": [{"rule": "DARB-PATH-001", "jewel": VAULT}],
                                     "notes": [unclassified_note(VAULT)]}
E["24_unclassified_bucket/ignore"] = {"derived_from": "after v0.1.0-rc.1: the vulnerable input with crown_jewels.unclassified: ignore",
                                      "findings": [no_default_deny(NS_RECORDS)],
                                      "absent": [{"rule": "DARB-PATH-001", "jewel": VAULT}],
                                      "notes": [ignored_note(VAULT)]}

# Phase 6 review, item 2 - 01_classic/key_outside_input: scenario 1 with the
# PII bucket encrypted by a key that is not in the input (aws_kms_key.pii
# removed; kms_master_key_id is a literal key ARN). The key's policy is
# unknown, so CAN_DECRYPT needs an unknown allow (KMS requires the key
# policy to allow): unconfirmed, confidence low, a coverage gap names the
# key. Worst case: 729, critical, as scenario 1. Cut: the decrypt has no
# side (DESIGN.md 9.1, SCORING.md 4.1-4.2): without the identity policies
# the unknown key policy may still allow, and the unknown key policy may
# let the role rewrite it (kms:PutKeyPolicy), so neither side counts. The
# Round 7: the key policy side rests only on the unknown key policy (the
# guard that it may let the role rewrite it is decided by the same
# resolution): resolve, 0, by scanning the key (its Terraform or plan, or a
# snapshot of its account). The cut is that resolve step; nothing is
# uncuttable any more; the alternative is the read, explicit: revoke,
# identity, 3.
# DARB-POST-008 on the role (kms:Decrypt on "*").
OUTSIDE_KEY = f"arn:aws:kms:us-east-1:{ACCT}:key/0b1c2d3e-0000-4000-8000-000000000001"
KEY_SCAN = "scan the key's Terraform or plan, or a snapshot of its account"
E["01_classic/key_outside_input"] = {"derived_from": "Phase 6 review, item 2: a KMS key outside the input", "findings": [
    path_finding("DARB-PATH-001", API, PII, [f"RUNS_AS {SA_API}", f"ASSUMES {ROLE}", f"CAN_READ_PLAINTEXT {PII}"],
                 729, "critical", [f"CAN_DECRYPT[for {PII}] {ROLE} -> {OUTSIDE_KEY}"], [f"CAN_READ {ROLE} -> {PII}"],
                 confirmed=False, confidence="low", defaults=IRSA_DEFAULTS, undecided=[OUTSIDE_KEY + " is not in the input"],
                 fix=[step(f"CAN_DECRYPT[for {PII}] {ROLE} -> {OUTSIDE_KEY}", "resource", "resolve", 0, resolve=KEY_SCAN)],
                 other_side=[], alternative_detail=[step(f"CAN_READ {ROLE} -> {PII}", "identity", "revoke", 3)]),
    broad_grant(ROLE), no_default_deny(NS_PAYMENTS)]}

# Phase 6 review, item 1 - 19_secrets_manager/unknown_managed_policy:
# scenario 19 with the AWS managed policy ReadOnlyAccess attached to
# payments-api; it is not in the vendored snapshot, so its document is an
# unknown Allow and an unknown Deny. The read and the decrypt are still
# granted by the role's inline policy and the key policy: their only
# unknown is a possible Deny: confirmed_unless_denied, confidence medium.
# The score is the worst case, no unknown Deny applying: 810, critical (it
# was 324 when confidence was a factor). Cut: under the worst case the
# unknown policy may let the role rewrite its own grants (iam:PutRolePolicy),
# the key policy (kms:PutKeyPolicy) and the secret's resource policy
# (secretsmanager:PutResourcePolicy): the key policy side is lost
# (SCORING.md 4.2). Rounds 5-6: the role's own edges keep their identity
# side. ReadOnlyAccess is not in the snapshot: its share of any grant is
# an unknown Allow, so it is resolved (0, tools/refresh-managed-policies),
# never detached (round 7). The decrypt's identity side is the inline
# kms:Decrypt on "*" (broad, narrow, 1) plus ReadOnlyAccess (resolve, 0);
# the read's is the inline GetSecretValue on the exact ARN (revoke, 3) plus
# the resolve; CAN_ESCALATE[iam:modify-policy] to "role with any
# permission" rests on ReadOnlyAccess alone (resolve, 0). Cuts:
# {decrypt, escalate} = 1 + 0 = 1; {read, escalate} = 3; the IRSA trust
# (:sub exact, revoke) 7. The cut is the first, pending resolution; the
# alternative sharing no edge with it is the trust ({read, escalate} shares
# the escalation).
TRUST_EDGE = f"ASSUMES {SA_API} -> {ROLE}"
UNKNOWN_DECRYPT = f"CAN_DECRYPT[for {SECRET}] {ROLE} -> {SECRET_KEY}"
UNKNOWN_ESCALATE = f"CAN_ESCALATE[iam:modify-policy] {ROLE} -> {ROLE}"
E["19_secrets_manager/unknown_managed_policy"] = {
    "derived_from": "Phase 6 review, item 1: an unknown AWS managed policy never lowers the severity", "findings": [
        path_finding("DARB-PATH-001", API, SECRET, [f"RUNS_AS {SA_API}", f"ASSUMES {ROLE}", f"CAN_READ_PLAINTEXT {SECRET}"],
                     810, "critical", [UNKNOWN_DECRYPT, UNKNOWN_ESCALATE], [TRUST_EDGE], confirmed=False,
                     status="confirmed_unless_denied", confidence="medium",
                     defaults=IRSA_DEFAULTS, undecided=["ReadOnlyAccess", "tools/refresh-managed-policies"],
                     fix=[step(UNKNOWN_DECRYPT, "identity", "narrow", 1),
                          step(UNKNOWN_DECRYPT, "identity", "resolve", 0, READ_ONLY, "tools/refresh-managed-policies"),
                          step(UNKNOWN_ESCALATE, "identity", "resolve", 0, READ_ONLY, "tools/refresh-managed-policies")],
                     other_side=[], alternative_detail=[step(TRUST_EDGE, "trust", "revoke", 7)]),
        # Phase 6 review, dominance (DESIGN.md 8): the unknown policy may let
        # payments-api rewrite its own policies (an unconfirmed escalation),
        # but payments-api reads the secret directly at a stronger status
        # (confirmed_unless_denied): dominated, no DARB-PATH-002.
        broad_grant(ROLE), no_default_deny(NS_PAYMENTS)]}

# 22 - one pair, two findings (Phase 6 review). apps/app (not exposed: 400)
# assumes role/app by IRSA. role/app reads the PII bucket (s3:GetObject on
# its objects, explicit) and decrypts its key under a condition on
# kms:EncryptionContext:aws:s3:arn whose value is var.pii_bucket_arn, a
# variable with no value: statically unresolved, so the decrypt needs an
# unknown allow. role/app may also sts:AssumeRole role/ops (whose trust names
# role/app); role/ops reads nothing but may iam:PutRolePolicy on itself, so
# it grants itself the read and the decrypt (role with any permission):
# confirmed.
#
# DARB-PATH-001 (the paths without an escalation): RUNS_AS, ASSUMES app,
# CAN_READ_PLAINTEXT: 3 edges (810): 400 x 810 = 324; x 900 = 291, medium;
# unconfirmed, confidence low; undecided names the variable and --plan. Cut
# (SCORING.md 4.1): the decrypt's identity grant rests only on its context
# condition, whose value is unresolved: resolve, 0, -var-file setting
# pii_bucket_arn (Phase 6 review, round 7; it was narrow, 1); the key policy
# is the default (the account root): narrow, resource, 2;
# the alternative is the explicit read: revoke, identity, 3. role/app can
# regain the access only through role/ops, another identity, so the cut
# holds (SCORING.md 4.2).
#
# DARB-PATH-002: RUNS_AS, ASSUMES app, ASSUMES ops, CAN_ESCALATE ops,
# CAN_READ_PLAINTEXT: 5 edges (656): 400 x 656 = 262; x 900 = 235, low;
# confirmed. Not dominated: role/ops has no access of its own. Nothing
# after the "any permission" node is cuttable (SCORING.md 4.2), but the edge
# into it is: CAN_ESCALATE ops -> ops is role/ops's own iam:PutRolePolicy on
# its ARN, explicit: revoke, identity, 4 (SCORING.md 4.1, IAM escalation);
# an IAM role has no resource policy for that action: no other side.
# ASSUMES app -> ops has one side only: role/ops's trust names role/app's
# ARN in the same account, and a same-account resource policy naming an IAM
# role ARN grants on its own (DESIGN.md 6, the "Same-account effect" table;
# IAM User Guide): without role/app's identity policies the assume is still
# allowed, so that side does not count (SCORING.md 4.1); the trust names
# role/app exactly: revoke, trust, 7. (Corrected at the Phase 6 review: the
# first derivation gave it an identity side, revoke, 3; the engine was
# right, open_mismatches group I.) The min-cut is the root cause itself:
# CAN_ESCALATE ops, revoke, identity, 4. The cheapest cut sharing no edge
# with it: the IRSA trust (7) or the ASSUMES trust (7), equal; closest to
# the entry: the IRSA trust. Neither cut breaks the other finding's path:
# also_fixes empty.
#
# DARB-POST-006 on the key (rotation by the Terraform default) and
# DARB-POST-007 on apps. The unresolved variable is a coverage gap: exit 3
# (no finding at or above high).
APP_ROLE = f"arn:aws:iam::{ACCT}:role/app"
OPS_ROLE = f"arn:aws:iam::{ACCT}:role/ops"
APP = f"k8s:{PROD}/apps/Deployment/app"
SA_APP = f"k8s:{PROD}/apps/ServiceAccount/app"
NS_APPS_22 = f"k8s:{PROD}//Namespace/apps"


def app_direct(confirmed):
    path = [f"RUNS_AS {SA_APP}", f"ASSUMES {APP_ROLE}", f"CAN_READ_PLAINTEXT {PII}"]
    if not confirmed:
        cut, alt = decrypt_cut(APP_ROLE, PII_KEY, PII)
        return path_finding("DARB-PATH-001", APP, PII, path, 291, "medium", cut, alt,
                            confirmed=False, confidence="low", defaults=IRSA_DEFAULTS, undecided=["pii_bucket_arn", "--plan"],
                            **{**pii_decrypt_fixes(cut, alt),
                               "fix": [step(cut[0], "identity", "resolve", 0, resolve="-var-file (pii_bucket_arn)")]})
    # Dominance variant (Phase 6 review, round 4). role/app reads the
    # bucket, decrypts with no condition (confirmed) and may iam:PutRolePolicy
    # on itself. Its escalation path (RUNS_AS, ASSUMES app, CAN_ESCALATE app,
    # CAN_READ_PLAINTEXT, confirmed) is dominated and hidden, but it stays in
    # this finding's cut (DESIGN.md 8): the cut must break both paths.
    # Capacities (SCORING.md 4.1):
    #   RUNS_AS 100; ASSUMES sa -> app, the IRSA trust names apps:app
    #   exactly: revoke, trust, 7 (role/app's side: none, IRSA);
    #   CAN_DECRYPT[for PII] app -> key: kms:Decrypt on the key ARN, no
    #   encryption-context condition, broad: narrow, identity, 1 (the
    #   default key policy, account root: narrow, resource, 2);
    #   CAN_READ app -> PII: s3:GetObject on the bucket's objects, explicit:
    #   revoke, identity, 3 (no bucket policy: no other side);
    #   CAN_ESCALATE app -> app: iam:PutRolePolicy on role/app's own ARN,
    #   explicit: revoke, identity, 4 (no other side);
    #   after the "any permission" node: uncuttable.
    # Cuts breaking both paths: {decrypt 1, escalate 4} = 5;
    # {read 3, escalate 4} = 7; {trust} = 7; {RUNS_AS} = 100. The min-cut is
    # 5. Cutting the decrypt alone (1) is not a cut: the escalation path
    # survives and becomes a DARB-PATH-002 (TestDominatedPathsStayInTheCut).
    # alternative_fix, the cheapest cut sharing no edge with it: the IRSA
    # trust, 7 (the {read, escalate} cut shares the escalation). Both
    # identity fixes are statements of role/app's one inline policy
    # (data-access): shared_fix_possible names role/app.
    decrypt = f"CAN_DECRYPT[for {PII}] {APP_ROLE} -> {PII_KEY}"
    escalate = f"CAN_ESCALATE[iam:modify-policy] {APP_ROLE} -> {APP_ROLE}"
    trust = f"ASSUMES {SA_APP} -> {APP_ROLE}"
    return path_finding("DARB-PATH-001", APP, PII, path, 291, "medium", [decrypt, escalate], [trust], defaults=IRSA_DEFAULTS,
                        fix=[step(decrypt, "identity", "narrow", 1), step(escalate, "identity", "revoke", 4)],
                        other_side=[step(decrypt, "resource", "narrow", 2)],
                        alternative_detail=[step(trust, "trust", "revoke", 7)], shared_fix=[APP_ROLE])


OPS_EDGE = f"ASSUMES {APP_ROLE} -> {OPS_ROLE}"
OPS_ESCALATE = f"CAN_ESCALATE[iam:modify-policy] {OPS_ROLE} -> {OPS_ROLE}"
E["22_direct_and_escalation/vulnerable"] = {
    "derived_from": "Phase 6 review: a pair with a direct finding and an escalation finding", "exit_code": 3,
    "distinct_fingerprints": True, "findings": [
        app_direct(False),
        path_finding("DARB-PATH-002", APP, PII,
                     [f"RUNS_AS {SA_APP}", f"ASSUMES {APP_ROLE}", f"ASSUMES {OPS_ROLE}", f"CAN_ESCALATE {OPS_ROLE}", f"CAN_READ_PLAINTEXT {PII}"],
                     235, "low", [OPS_ESCALATE], [f"ASSUMES {SA_APP} -> {APP_ROLE}"], defaults=IRSA_DEFAULTS,
                     fix=[step(OPS_ESCALATE, "identity", "revoke", 4)], other_side=[],
                     alternative_detail=[step(f"ASSUMES {SA_APP} -> {APP_ROLE}", "trust", "revoke", 7)]),
        rotation_off(PII_KEY), no_default_deny(NS_APPS_22)]}
E["22_direct_and_escalation/fixed"] = {
    "derived_from": "Phase 6 review, fixed: role/ops can no longer rewrite its own policy", "exit_code": 3, "findings": [
        app_direct(False), rotation_off(PII_KEY), no_default_deny(NS_APPS_22)],
    "absent": [{"rule": "DARB-PATH-002", "entry": APP, "jewel": PII}]}
E["22_direct_and_escalation/dominance"] = {
    "derived_from": "Phase 6 review, dominance: role/app decrypts (confirmed) and rewrites its own policy; no role/ops",
    "exit_code": 0, "findings": [app_direct(True), rotation_off(PII_KEY), no_default_deny(NS_APPS_22)],
    "absent": [{"rule": "DARB-PATH-002", "entry": APP, "jewel": PII}]}

# Remediation strategies (Phase 5 review). A root-cause fix narrows the
# broad Allow to what declared intended access uses through it; without
# intended access it is an unverified suggestion, the mitigation (a Deny for
# this path only) comes first, with the advice to declare intended access.
NOTE_INTENDED = "declare intended_access to get a verified root-cause fix"
MITIGATION_FIRST = {"order": ["mitigation", "root-cause"], "verified": [True, False], "note": NOTE_INTENDED}


def with_remediation(variant, rule, jewel, remediation):
    for f in E[variant]["findings"]:
        if f["rule"] == rule and f.get("jewel") == jewel:
            f["remediation"] = remediation
            return
    raise KeyError(variant)


# 1 and 6: kms:Decrypt / sts:AssumeRole on "*", no intended access declared.
with_remediation("01_classic/vulnerable", "DARB-PATH-001", PII, MITIGATION_FIRST)
with_remediation("06_role_chain_cross_account/vulnerable", "DARB-PATH-001", WAREHOUSE, MITIGATION_FIRST)
# 10: UNKNOWN until the organization ID is known: what is missing, no fix.
with_remediation("10_kms_principal_org_id/vulnerable", "DARB-PATH-001", PII, {"missing": True})

# 1b - scenario 1 plus the API's legitimate use, declared: it reads the
# payment receipts bucket (its own KMS key). The PII path is scenario 1's
# (729, critical; cut: the broad decrypt, identity, narrow, 1). The intended
# path decrypts the receipts key through DecryptAnything, so the root cause
# narrows its Resource from "*" to exactly that key: it removes the PII
# decrypt and keeps the intended read; verified, it comes first, then the
# mitigation (also verified). The receipts key has no rotation (as in 1
# fixed). The fixed variant is that root-cause fix applied.
E["01b_classic_intended/vulnerable"] = {"derived_from": "Phase 5 review: scenario 1 with intended_access declared",
    "findings": [classic(), rotation_off(RECEIPTS_KEY), no_default_deny(NS_PAYMENTS), broad_grant(ROLE)],
    # api reads the unclassified receipts bucket as declared: not reported.
    "absent": [{"rule": "DARB-PATH-001", "jewel": RECEIPTS}],
    "intended_access": intended("verified"), "notes": [unclassified_note(RECEIPTS)]}
with_remediation("01b_classic_intended/vulnerable", "DARB-PATH-001", PII, {"order": ["root-cause", "mitigation"], "verified": [True, True]})
E["01b_classic_intended/fixed"] = {"derived_from": "Phase 5 review: the root-cause fix of 1b applied (kms:Decrypt on the receipts key only)",
    "findings": [rotation_off(RECEIPTS_KEY), no_default_deny(NS_PAYMENTS)],
    "absent": ABSENT_PII + [{"rule": "DARB-PATH-001", "jewel": RECEIPTS}],
    "intended_access": intended("verified"), "notes": [unclassified_note(RECEIPTS)]}


# Fingerprints (DESIGN.md 5 "Stable IDs", 8 "Fingerprint", 8.1 "Posture
# finding identities"), written from the documents, not from the engine:
# a node ID is sha256("darb/v1" NUL kind NUL canonical identity); a path
# fingerprint sha256("darb/fingerprint/v1" NUL rule NUL major NUL entry ID
# NUL jewel ID), a posture one the same with the resource ID. Every rule of
# the catalog is at major version 1. The kind follows from the canonical
# identity's form (DESIGN.md 5).
def kind_of(identity):
    if identity == "anonymous":
        return "aws:anonymous"
    if identity.startswith("eks-nodegroup:"):
        return "aws:eks:nodegroup"
    if identity.startswith("k8s:"):
        if "//Namespace/" in identity:
            return "k8s:namespace"
        if "/Secret/" in identity:
            return "k8s:secret"
        return "k8s:workload"
    if identity.startswith("arn:aws:s3:::"):
        return "aws:s3:bucket"
    if identity.startswith("arn:aws:secretsmanager:"):
        return "aws:secretsmanager:secret"
    if identity.startswith("arn:aws:ssm:") and ":parameter/" in identity:
        return "aws:ssm:parameter"
    if ":role/" in identity:
        return "aws:iam:role"
    assert identity.startswith("arn:aws:kms:"), identity
    return "aws:kms:key"


def node_id(identity):
    return hashlib.sha256("\0".join(["darb/v1", kind_of(identity), identity]).encode()).hexdigest()


def fingerprint(f):
    ids = [node_id(f["resource"])] if "resource" in f else [node_id(f["entry"]), node_id(f["jewel"])]
    return hashlib.sha256("\0".join(["darb/fingerprint/v1", f["rule"], "1", *ids]).encode()).hexdigest()


def write(name, doc):
    out = {"format": "darb-expected/v1"}
    out.update(doc)
    out["findings"] = [{**f, "fingerprint": fingerprint(f)} for f in out.get("findings", [])]
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
