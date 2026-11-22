package access

import (
	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/eval/condition"
	"github.com/r3oof-900/darb/internal/eval/match"
	"github.com/r3oof-900/darb/internal/model"
)

// EKS Pod Identity (EKS User Guide › "EKS Pod Identity", "Create the role",
// "Grant pods access to AWS resources based on tags"):
//
//   - the service principal pods.eks.amazonaws.com assumes the association's
//     role: the trust policy must allow sts:AssumeRole and, because EKS
//     passes session tags, sts:TagSession — "For roles without this
//     permission in the trust policy, the AssumeRole operation fails" (IAM
//     User Guide › "Passing session tags in AWS STS");
//   - the session tags are eks-cluster-arn, eks-cluster-name,
//     kubernetes-namespace, kubernetes-service-account, kubernetes-pod-name
//     and kubernetes-pod-uid, all transitive; a trust policy sees them as
//     aws:RequestTag/<key>, aws:TagKeys and sts:TransitiveTagKeys;
//   - disableSessionTags removes the tags (and the need for sts:TagSession);
//   - the eks-pod-identity-agent add-on is required.
const (
	PodIdentityService = "pods.eks.amazonaws.com"
	PodIdentityAgent   = "eks-pod-identity-agent"
)

// PodIdentityTagKeys returns the session tag keys EKS Pod Identity adds.
func PodIdentityTagKeys() []string {
	return []string{
		"eks-cluster-arn", "eks-cluster-name", "kubernetes-namespace",
		"kubernetes-service-account", "kubernetes-pod-name", "kubernetes-pod-uid",
	}
}

// AssociationsFor returns the Pod Identity associations of a service account.
func AssociationsFor(inv *model.Inventory, sa *model.ServiceAccount) []*model.PodIdentityAssociation {
	var out []*model.PodIdentityAssociation
	for _, a := range inv.PodIdentity {
		if a.Cluster == sa.Cluster && a.Namespace == sa.Namespace && a.ServiceAccount == sa.Name {
			out = append(out, a)
		}
	}
	return out
}

// AgentInstalled is True when the input shows the eks-pod-identity-agent
// add-on on the cluster. Its absence from the input is not evidence that it
// is missing (it may be installed outside Terraform), so that is Unknown.
func AgentInstalled(inv *model.Inventory, cluster string) model.Tri {
	for _, a := range inv.Addons {
		if a.Cluster == cluster && a.Name == PodIdentityAgent {
			return model.True
		}
	}
	return model.Unknown
}

// PodIdentityRequest is the request pods.eks.amazonaws.com makes for the
// association's role, with the session tags as request context. Tag values
// that are not known (the pod name and UID, a cluster ARN not in the input)
// are unknown; every other context key is unknown.
func PodIdentityRequest(a *model.PodIdentityAssociation, cluster *model.Cluster, roleAccount, action string) *eval.Request {
	in := &condition.Input{Default: condition.StateUnknown, Present: map[string][]string{}}
	switch a.SessionTagsDisabled {
	case model.False:
		values := map[string]string{
			"eks-cluster-arn": cluster.ARN, "eks-cluster-name": a.Cluster,
			"kubernetes-namespace": a.Namespace, "kubernetes-service-account": a.ServiceAccount,
		}
		for _, k := range PodIdentityTagKeys() {
			if v := values[k]; v != "" && !model.ContainsUnresolved(v) {
				in.Present["aws:RequestTag/"+k] = []string{v}
			} else {
				in.Unknown = append(in.Unknown, "aws:RequestTag/"+k)
			}
		}
		in.Present["aws:TagKeys"] = PodIdentityTagKeys()
		in.Present["sts:TransitiveTagKeys"] = PodIdentityTagKeys()
	case model.True:
		in.Absent = append(in.Absent, "aws:TagKeys", "sts:TransitiveTagKeys")
		for _, k := range PodIdentityTagKeys() {
			in.Absent = append(in.Absent, "aws:RequestTag/"+k)
		}
	case model.Unknown:
	}
	return &eval.Request{
		Principal:       match.RequestPrincipal{Kind: match.KindService, ARN: PodIdentityService},
		Action:          action,
		Resource:        a.RoleARN,
		ResourceAccount: roleAccount,
		Context:         condition.NewContext(in),
	}
}

// PodIdentityResult is the decision for one association.
type PodIdentityResult struct {
	Verdict    eval.Verdict
	AssumeRole eval.Verdict // sts:AssumeRole on the role's trust policy
	TagSession eval.Verdict // sts:TagSession; required unless session tags are disabled
	Agent      model.Tri
}

// PodIdentityAssume decides whether a pod using the association's service
// account gets credentials for the association's role. Both trust decisions
// go through the evaluator. The result is ALLOW only when AssumeRole is
// allowed, TagSession is allowed or not needed, and the agent is installed;
// a definite denial of either needed action denies; anything else is UNKNOWN.
// A target role (targetRoleArn) is a further sts:AssumeRole by this role's
// session, decided like any role chain.
func PodIdentityAssume(a *model.PodIdentityAssociation, cluster *model.Cluster, trust *model.PolicyDocument, roleAccount string, agent model.Tri) PodIdentityResult {
	ps := TrustPolicySet(trust)
	r := PodIdentityResult{
		AssumeRole: eval.Evaluate(PodIdentityRequest(a, cluster, roleAccount, "sts:AssumeRole"), ps).Verdict,
		TagSession: eval.Evaluate(PodIdentityRequest(a, cluster, roleAccount, "sts:TagSession"), ps).Verdict,
		Agent:      agent,
	}
	switch a.SessionTagsDisabled {
	case model.False:
		r.Verdict = both(r.AssumeRole, r.TagSession)
	case model.True:
		r.Verdict = r.AssumeRole
	case model.Unknown:
		r.Verdict = r.AssumeRole
		if r.Verdict == eval.Allow && r.TagSession != eval.Allow {
			r.Verdict = eval.Unknown // needed only if tags are enabled
		}
	}
	if r.Verdict == eval.Allow && agent != model.True {
		r.Verdict = eval.Unknown
		if agent == model.False {
			r.Verdict = eval.ImplicitDeny // no agent: no credentials
		}
	}
	return r
}

// both is the verdict of two requests that must both be allowed.
func both(a, b eval.Verdict) eval.Verdict {
	switch {
	case a == eval.Deny || b == eval.Deny:
		return eval.Deny
	case a == eval.ImplicitDeny || b == eval.ImplicitDeny:
		return eval.ImplicitDeny
	case a == eval.Unknown || b == eval.Unknown:
		return eval.Unknown
	}
	return eval.Allow
}
