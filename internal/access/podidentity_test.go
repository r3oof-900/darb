package access

import (
	"slices"
	"testing"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/model"
)

const (
	podRole    = "arn:aws:iam::111122223333:role/payments-api"
	clusterARN = "arn:aws:eks:us-east-1:111122223333:cluster/prod"
)

// podTrust is a trust policy for pods.eks.amazonaws.com with the given
// actions, conditions and extra statements.
func podTrust(t *testing.T, actions, condition, extra string) *model.PolicyDocument {
	t.Helper()
	cond := ""
	if condition != "" {
		cond = `,"Condition":` + condition
	}
	return trust(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":`+
		actions+cond+`}`+extra+`]}`)
}

// The documented trust policy (EKS User Guide › "Create the role") and
// variants, decided through the evaluator for both actions.
func TestPodIdentityAssume(t *testing.T) {
	both := `["sts:AssumeRole","sts:TagSession"]`
	scoped := `{"StringEquals":{"aws:RequestTag/kubernetes-namespace":"payments","aws:RequestTag/kubernetes-service-account":"api"}}`
	cases := []struct {
		name                string
		doc                 *model.PolicyDocument
		ns, sa              string
		tagsDisabled, agent model.Tri
		arn                 string
		want                eval.Verdict
	}{
		{"documented trust", podTrust(t, both, "", ""), "payments", "api", model.False, model.True, clusterARN, eval.Allow},
		{"agent not shown in the input", podTrust(t, both, "", ""), "payments", "api", model.False, model.Unknown, clusterARN, eval.Unknown},
		{"agent missing", podTrust(t, both, "", ""), "payments", "api", model.False, model.False, clusterARN, eval.ImplicitDeny},
		{"no sts:TagSession: AssumeRole with tags fails", podTrust(t, `"sts:AssumeRole"`, "", ""), "payments", "api", model.False, model.True, clusterARN, eval.ImplicitDeny},
		{"no sts:TagSession, session tags disabled", podTrust(t, `"sts:AssumeRole"`, "", ""), "payments", "api", model.True, model.True, clusterARN, eval.Allow},
		{"no sts:TagSession, session tags unknown", podTrust(t, `"sts:AssumeRole"`, "", ""), "payments", "api", model.Unknown, model.True, clusterARN, eval.Unknown},
		{"scoped to payments/api", podTrust(t, both, scoped, ""), "payments", "api", model.False, model.True, clusterARN, eval.Allow},
		{"scoped, other service account", podTrust(t, both, scoped, ""), "tools", "default", model.False, model.True, clusterARN, eval.ImplicitDeny},
		{"scoped, session tags disabled", podTrust(t, both, scoped, ""), "payments", "api", model.True, model.True, clusterARN, eval.ImplicitDeny},
		{"scoped, session tags unknown", podTrust(t, both, scoped, ""), "payments", "api", model.Unknown, model.True, clusterARN, eval.Unknown},
		{"pod name is not known", podTrust(t, both, `{"StringEquals":{"aws:RequestTag/kubernetes-pod-name":"api-0"}}`, ""), "payments", "api", model.False, model.True, clusterARN, eval.Unknown},
		{"cluster ARN matches", podTrust(t, both, `{"StringEquals":{"aws:RequestTag/eks-cluster-arn":"`+clusterARN+`"}}`, ""), "payments", "api", model.False, model.True, clusterARN, eval.Allow},
		{"cluster ARN differs", podTrust(t, both, `{"StringEquals":{"aws:RequestTag/eks-cluster-arn":"`+clusterARN+`"}}`, ""), "payments", "api", model.False, model.True, clusterARN + "-dev", eval.ImplicitDeny},
		{"cluster ARN not in the input", podTrust(t, both, `{"StringEquals":{"aws:RequestTag/eks-cluster-arn":"`+clusterARN+`"}}`, ""), "payments", "api", model.False, model.True, "", eval.Unknown},
		{"explicit deny of sts:TagSession", podTrust(t, both, "", `,{"Effect":"Deny","Principal":"*","Action":"sts:TagSession"}`), "payments", "api", model.False, model.True, clusterARN, eval.Deny},
		{"source account is not in the request", podTrust(t, both, `{"StringEquals":{"aws:SourceAccount":"111122223333"}}`, ""), "payments", "api", model.False, model.True, clusterARN, eval.Unknown},
	}
	for _, c := range cases {
		a := &model.PodIdentityAssociation{Cluster: "prod", Namespace: c.ns, ServiceAccount: c.sa, RoleARN: podRole, SessionTagsDisabled: c.tagsDisabled}
		cl := &model.Cluster{Name: "prod", ARN: c.arn}
		if got := PodIdentityAssume(a, cl, c.doc, "111122223333", c.agent); got.Verdict != c.want {
			t.Errorf("%s: %s, want %s (%+v)", c.name, got.Verdict, c.want, got)
		}
	}
	ec2 := trust(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":["sts:AssumeRole","sts:TagSession"]}]}`)
	a := &model.PodIdentityAssociation{Cluster: "prod", Namespace: "payments", ServiceAccount: "api", RoleARN: podRole}
	if got := PodIdentityAssume(a, &model.Cluster{Name: "prod"}, ec2, "111122223333", model.True); got.Verdict != eval.ImplicitDeny {
		t.Errorf("a role not trusting pods.eks.amazonaws.com: %s", got.Verdict)
	}
}

func TestPodIdentityRequestContext(t *testing.T) {
	a := &model.PodIdentityAssociation{Cluster: "prod", Namespace: "payments", ServiceAccount: "api", RoleARN: podRole}
	req := PodIdentityRequest(a, &model.Cluster{Name: "prod", ARN: clusterARN}, "111122223333", "sts:TagSession")
	if req.Principal.ARN != PodIdentityService || req.Action != "sts:TagSession" || req.Resource != podRole {
		t.Errorf("request %+v", req)
	}
	if v := req.Context.Lookup("aws:RequestTag/kubernetes-namespace"); !slices.Equal(v.Values, []string{"payments"}) {
		t.Errorf("namespace tag %+v", v)
	}
	if v := req.Context.Lookup("aws:TagKeys"); len(v.Values) != 6 {
		t.Errorf("aws:TagKeys %+v", v)
	}
}

func TestAssociationsAndAgent(t *testing.T) {
	inv := &model.Inventory{
		PodIdentity: []*model.PodIdentityAssociation{
			{Cluster: "prod", Namespace: "payments", ServiceAccount: "api", RoleARN: podRole},
			{Cluster: "dev", Namespace: "payments", ServiceAccount: "api", RoleARN: podRole},
		},
		Addons: []*model.ClusterAddon{{Cluster: "prod", Name: PodIdentityAgent}, {Cluster: "dev", Name: "vpc-cni"}},
	}
	sa := &model.ServiceAccount{Cluster: "prod", Namespace: "payments", Name: "api"}
	if got := AssociationsFor(inv, sa); len(got) != 1 || got[0].Cluster != "prod" {
		t.Errorf("associations %+v", got)
	}
	if AgentInstalled(inv, "prod") != model.True || AgentInstalled(inv, "dev") != model.Unknown {
		t.Error("agent")
	}
}
