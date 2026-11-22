package access

import (
	"strings"

	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/eval/condition"
	"github.com/r3oof-900/darb/internal/eval/match"
	"github.com/r3oof-900/darb/internal/model"
)

// IRSARequest is the sts:AssumeRoleWithWebIdentity request a pod running as
// sa makes for roleARN (EKS User Guide › "IAM roles for service accounts"):
//
//   - principal: Federated = arn:<partition>:iam::<role account>:oidc-provider/<issuer host+path>
//   - context:   <issuer>:sub = system:serviceaccount:<namespace>:<name>
//     <issuer>:aud = the service account's audience (sts.amazonaws.com by default)
//
// The issuer comes from the cluster. When it is unknown, the provider ARN is
// an unresolved placeholder and the issuer-scoped keys cannot be named, so
// the trust decision is UNKNOWN: the trust policy is still evaluated by the
// evaluator, never short-circuited. Every other context key is unknown.
func IRSARequest(sa *model.ServiceAccount, cluster *model.Cluster, roleARN, roleAccount, partition string) *eval.Request {
	issuer := strings.TrimSuffix(strings.TrimPrefix(cluster.OIDCIssuer, "https://"), "/")
	in := &condition.Input{Default: condition.StateUnknown, Present: map[string][]string{}}
	provider := model.UnresolvedPlaceholder("oidc_issuer_of_cluster_" + strings.NewReplacer(":", "_", "/", "_").Replace(cluster.Key()))
	if issuer != "" {
		provider = "arn:" + partition + ":iam::" + roleAccount + ":oidc-provider/" + issuer
		in.Present[issuer+":sub"] = []string{sa.SubjectString()}
		in.Present[issuer+":aud"] = []string{sa.Audience}
	}
	return &eval.Request{
		Principal:       match.RequestPrincipal{Kind: match.KindWebIdentity, ARN: provider},
		Action:          "sts:AssumeRoleWithWebIdentity",
		Resource:        roleARN,
		ResourceAccount: roleAccount,
		Context:         condition.NewContext(in),
	}
}

// TrustPolicySet evaluates a role's trust policy: a resource-based policy
// that must allow (docs/DESIGN.md section 6.1).
func TrustPolicySet(trust *model.PolicyDocument) *eval.PolicySet {
	return &eval.PolicySet{Resource: []*model.PolicyDocument{trust}, ResourcePolicyRequired: true}
}
