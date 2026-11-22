// Package posture holds the single-resource posture rules (DESIGN.md §8.1).
// They fire only on definite settings: stated in the input, or a documented
// deterministic default (DESIGN.md §4.7), which the finding lists in
// defaults_used. A setting with no deterministic default is a coverage gap,
// never a finding and never "compliant".
package posture

import (
	"slices"

	"github.com/r3oof-900/darb/internal/access"
	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/rules"
	"github.com/r3oof-900/darb/internal/scoring"
)

// Rule IDs.
const (
	IRSATrustAnySA     = "DARB-POST-001"
	IMDSv1             = "DARB-POST-002"
	Privileged         = "DARB-POST-003"
	AutomountWithRBAC  = "DARB-POST-004"
	PublicAccessOff    = "DARB-POST-005"
	KeyRotationOff     = "DARB-POST-006"
	NoDefaultDenyNetPo = "DARB-POST-007"
)

// ProbeSubject is a service account that is not in any input: a trust that
// allows it allows service accounts it was not written for.
const ProbeSubject = "darb-probe"

type rule struct {
	meta       rules.Meta
	confidence graph.Confidence
	check      func(in *rules.Input) []hit
}

type hit struct {
	// base overrides the rule's base severity for this hit (0: the rule's).
	base     int
	resource string
	id       model.ID
	location model.SourceLocation
	defaults []string
	evidence []string
}

func (r *rule) Meta() rules.Meta { return r.meta }

func (r *rule) Evaluate(in *rules.Input) []rules.Finding {
	var out []rules.Finding
	hits := r.check(in)
	for i := range hits {
		h := &hits[i]
		base := r.meta.Base
		if h.base != 0 {
			base = h.base
		}
		score, severity := scoring.Posture(base, r.confidence)
		out = append(out, rules.Finding{
			Resource: h.resource, ResourceID: h.id, DefaultsUsed: h.defaults, Evidence: h.evidence, Location: h.location,
			Confirmed: true, Confidence: r.confidence.String(),
			Factors: scoring.Factors{Score: score, Severity: severity, Confidence: scoring.ConfidenceWeight(r.confidence)},
		})
	}
	return out
}

func ref(t, u string) rules.Reference { return rules.Reference{Title: t, URL: u} }

func meta(id, title, rationale string, base int, techniques []string, refs []rules.Reference, failing, passing []string) rules.Meta {
	return metaV(id, "1.0.0", title, rationale, base, techniques, refs, failing, passing)
}

func metaV(id, version, title, rationale string, base int, techniques []string, refs []rules.Reference, failing, passing []string) rules.Meta {
	return rules.Meta{
		ID: id, Version: version, Kind: rules.KindPosture, Title: title, Rationale: rationale, Base: base,
		Techniques: techniques, References: refs, Failing: failing, Passing: passing,
	}
}

// Rules returns the posture rules.
func Rules() []rules.Rule {
	return []rules.Rule{
		&rule{
			metaV(IRSATrustAnySA, "1.0.1", "IRSA trust policy accepts any service account",
				"The trust policy allows sts:AssumeRoleWithWebIdentity for a service account it was not written for (wildcard :sub, or :aud only): any pod of the cluster, or of a namespace (a wildcard scoped to it), that gets an STS token can assume the role. Probed with a service account not in the input, in a namespace of its own and in every namespace of the cluster.",
				scoring.BaseHigh, []string{"T1078.004"},
				[]rules.Reference{ref("EKS › Configure the role trust policy", "https://docs.aws.amazon.com/eks/latest/userguide/associate-service-account-role.html")},
				[]string{"04_wildcard_sub/vulnerable", "05_aud_only/vulnerable"}, []string{"04_wildcard_sub/fixed", "05_aud_only/fixed"}),
			graph.High, irsaTrust,
		},
		&rule{
			meta(IMDSv1, "Node group allows IMDSv1",
				"IMDSv1 answers any request from a pod: the node's instance role credentials are one HTTP GET away.",
				scoring.BaseHigh, []string{"T1552.005"},
				[]rules.Reference{ref("EC2 › Use IMDSv2", "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html")},
				[]string{"09_hostnetwork_imds/vulnerable"}, []string{"09_hostnetwork_imds/fixed"}),
			graph.High, imdsV1,
		},
		&rule{
			meta(Privileged, "Container runs privileged",
				"A privileged container is essentially root on the host: it can reach the node's credentials and every pod on it.",
				scoring.BaseHigh, []string{"T1611"},
				[]rules.Reference{ref("Kubernetes › Pod Security Standards (Baseline: privileged containers)", "https://kubernetes.io/docs/concepts/security/pod-security-standards/")},
				[]string{"test:TestPostureRules/privileged"}, []string{"01_classic/vulnerable"}),
			graph.High, privileged,
		},
		&rule{
			meta(AutomountWithRBAC, "Service account token mounted in a workload whose account has RBAC permissions",
				"The token gives anyone in the pod the service account's Kubernetes permissions; mount it only where the workload calls the API.",
				scoring.BaseMedium, []string{"T1528"},
				[]rules.Reference{ref("Kubernetes › Service accounts (opt out of automounting)", "https://kubernetes.io/docs/concepts/security/service-accounts/")},
				[]string{"08_rbac_create_pods/vulnerable"}, []string{"01_classic/vulnerable"}),
			graph.High, automount,
		},
		&rule{
			meta(PublicAccessOff, "Crown-jewel bucket has Block Public Access off",
				"With restrict_public_buckets off, a public bucket policy takes effect: one policy edit away from public data.",
				scoring.BaseHigh, []string{"T1530"},
				[]rules.Reference{ref("Amazon S3 › Blocking public access", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html")},
				[]string{"12_public_bucket/vulnerable"}, []string{"12_public_bucket/fixed"}),
			graph.High, publicAccessOff,
		},
		&rule{
			meta(KeyRotationOff, "KMS key rotation is off",
				"Without automatic rotation a customer managed key's material never changes, so exposure of the material lasts.",
				scoring.BaseMedium, nil,
				[]rules.Reference{ref("KMS › Rotate keys", "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html")},
				[]string{"06_role_chain_cross_account/vulnerable"}, []string{"01_classic/vulnerable"}),
			graph.High, keyRotation,
		},
		&rule{
			meta(NoDefaultDenyNetPo, "Namespace has no default-deny ingress NetworkPolicy",
				"Without a default deny, every pod accepts traffic from every other pod, so one compromised pod reaches all.",
				scoring.BaseMedium, nil,
				[]rules.Reference{ref("Kubernetes › Network Policies (default deny)", "https://kubernetes.io/docs/concepts/services-networking/network-policies/")},
				[]string{"01_classic/vulnerable"}, []string{"test:TestPostureRules/default-deny"}),
			graph.Medium, defaultDeny,
		},
		&rule{
			metaV(BroadGrant, "1.1.0", "Sensitive action granted on every resource or to every principal",
				"kms:Decrypt, sts:AssumeRole, iam:PassRole, s3:GetObject, secretsmanager:GetSecretValue or ssm:GetParameter on \"*\" (or to Principal \"*\"), scoped at most to an organization or account: every new key, role, bucket or secret is reachable the moment it exists. A fix that blocks one path leaves this grant; this finding keeps it in view. High when an entry point reaches the principal holding the grant, medium when none does (accounts hold intended admin roles); the evidence says which entries (reachable_from).",
				scoring.BaseHigh, []string{"T1078.004"},
				[]rules.Reference{ref("IAM › Security best practices: apply least-privilege permissions", "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html")},
				[]string{"01_classic/vulnerable", "10_kms_principal_org_id/vulnerable"}, []string{"01_classic/fixed", "11_boundary_deny/fixed"}),
			graph.High, broadGrants,
		},
	}
}

func irsaTrust(in *rules.Input) []hit {
	var out []hit
	for _, t := range in.Inventory.Trusts {
		role := principal(in.Inventory, t.Role())
		if allowed := probeAllowed(in, t, role); allowed != "" {
			out = append(out, hit{resource: role.Identity(), id: role.ID(), location: *role.Source(), evidence: []string{"trust " + t.Policy().ID() + " allows " + allowed}})
		}
	}
	return out
}

// probeAllowed: the subject of a service account that is not in the input
// (named darb-probe) that the trust allows, in a namespace of its own or
// in any namespace the cluster has in the input — a wildcard scoped to one
// namespace ("system:serviceaccount:ns:*") accepts every new service
// account there; "" when none is allowed.
func probeAllowed(in *rules.Input, t *model.TrustRelationship, role *model.Principal) string {
	for _, c := range in.Inventory.Clusters {
		if c.OIDCIssuer == "" {
			continue
		}
		for _, ns := range probeNamespaces(in.Inventory, c.Key()) {
			probe := &model.ServiceAccount{Cluster: c.Key(), Namespace: ns, Name: ProbeSubject, Audience: "sts.amazonaws.com"}
			req := access.IRSARequest(probe, c, role.Identity(), role.Account(), in.Partition)
			if d := eval.Evaluate(req, access.TrustPolicySet(t.Policy())); d.Verdict == eval.Allow {
				return probe.SubjectString()
			}
		}
	}
	return ""
}

// probeNamespaces: a namespace of the probe's own, then every namespace
// of the cluster in the input, sorted.
func probeNamespaces(inv *model.Inventory, cluster string) []string {
	seen := map[string]bool{}
	for _, sa := range inv.ServiceAccounts {
		if sa.Cluster == cluster {
			seen[sa.Namespace] = true
		}
	}
	for _, w := range inv.Workloads {
		if w.Cluster() == cluster {
			seen[w.Namespace()] = true
		}
	}
	delete(seen, ProbeSubject)
	nss := make([]string, 0, len(seen))
	for ns := range seen {
		nss = append(nss, ns)
	}
	slices.Sort(nss)
	return append([]string{ProbeSubject}, nss...)
}

func principal(inv *model.Inventory, id model.ID) *model.Principal {
	for _, p := range inv.Principals {
		if p.ID() == id {
			return p
		}
	}
	return model.NewPrincipal(model.KindIAMRole, string(id), "", &model.SourceLocation{})
}

func imdsV1(in *rules.Input) []hit {
	var out []hit
	for _, ng := range in.Inventory.NodeGroups {
		if ng.HTTPTokens == "optional" {
			id := "eks-nodegroup:" + ng.Cluster + "/" + ng.Name
			out = append(out, hit{resource: id, id: model.NewID(model.KindEKSNodeGroup, id), location: ng.Source, evidence: []string{"http_tokens = optional at " + ng.Source.String()}})
		}
	}
	return out
}

func privileged(in *rules.Input) []hit {
	var out []hit
	for _, w := range in.Inventory.Workloads {
		if w.Privileged() {
			out = append(out, hit{resource: w.Identity(), id: w.ID(), location: *w.Source(), evidence: []string{"privileged: true at " + w.Source().String()}})
		}
	}
	return out
}

func automount(in *rules.Input) []hit {
	hasRBAC := map[string]bool{}
	for _, g := range in.Inventory.RBAC {
		if g.SubjectKind == "ServiceAccount" && (len(g.Rules) > 0 || g.Unresolved != "") {
			hasRBAC[g.Cluster+"/"+g.SubjectNamespace+"/"+g.SubjectName] = true
		}
	}
	var out []hit
	for _, w := range in.Inventory.Workloads {
		if w.AutomountToken() == model.True && hasRBAC[w.Cluster()+"/"+w.Namespace()+"/"+w.ServiceAccount()] {
			h := hit{resource: w.Identity(), id: w.ID(), location: *w.Source(), evidence: []string{"service account " + w.ServiceAccount() + " has RBAC permissions"}}
			if slices.Contains(w.Defaulted(), model.DefaultAutomountToken) {
				h.defaults = []string{model.DefaultAutomountToken}
			}
			out = append(out, h)
		}
	}
	return out
}

func publicAccessOff(in *rules.Input) []hit {
	var out []hit
	for _, j := range in.Jewels {
		if j.Kind() == model.KindS3Bucket && in.Inventory.RestrictPublic(j) == model.False {
			ev := []string{"restrict_public_buckets = false at " + j.Source().String()}
			for _, a := range in.Inventory.AccountBlocks {
				if a.Account == j.Account() {
					ev = append(ev, "account "+a.Account+" restrict_public_buckets = false at "+a.Source.String())
				}
			}
			out = append(out, hit{resource: j.ARN(), id: j.ID(), location: *j.Source(), evidence: ev})
		}
	}
	return out
}

func keyRotation(in *rules.Input) []hit {
	var out []hit
	for _, r := range in.Inventory.Resources {
		if r.Kind() == model.KindKMSKey && r.KeyRotation() == model.False {
			h := hit{resource: r.ARN(), id: r.ID(), location: *r.Source(), evidence: []string{"key at " + r.Source().String()}}
			if slices.Contains(r.Defaulted(), model.DefaultKeyRotationTF) {
				h.defaults = []string{model.DefaultKeyRotationTF}
			}
			out = append(out, h)
		}
	}
	return out
}

func defaultDeny(in *rules.Input) []hit {
	denied := map[string]bool{}
	for _, p := range in.Inventory.NetworkPolicies {
		if p.DefaultDenyIngress() {
			denied[p.Cluster+"/"+p.Namespace] = true
		}
	}
	seen := map[string]bool{}
	var out []hit
	for _, w := range in.Inventory.Workloads {
		key := w.Cluster() + "/" + w.Namespace()
		if denied[key] || seen[key] {
			continue
		}
		seen[key] = true
		id := model.K8sIdentity(w.Cluster(), "", "Namespace", w.Namespace())
		out = append(out, hit{resource: id, id: model.NewID(model.KindK8sNamespace, id), location: *w.Source(), evidence: []string{"no NetworkPolicy selects every pod for ingress with no rules"}})
	}
	return out
}
