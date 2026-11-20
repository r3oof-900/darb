package posture

import (
	"testing"

	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/iampolicy"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/rules"
)

func run(t *testing.T, id string, in *rules.Input) []rules.Finding {
	t.Helper()
	for _, r := range Rules() {
		if r.Meta().ID == id {
			return r.Evaluate(in)
		}
	}
	t.Fatalf("no rule %s", id)
	return nil
}

func workload(name string, privileged bool, mount model.Tri, defaulted ...string) *model.Workload {
	return model.NewWorkload(&model.WorkloadInput{
		Cluster: "prod", Namespace: "ns", Kind: "Deployment", Name: name, ServiceAccount: name,
		Privileged: privileged, AutomountToken: mount, Defaulted: defaulted,
	})
}

func TestPostureRules(t *testing.T) {
	t.Run("privileged", func(t *testing.T) {
		in := &rules.Input{Inventory: &model.Inventory{Workloads: []*model.Workload{workload("root", true, model.True), workload("plain", false, model.True)}}}
		if fs := run(t, Privileged, in); len(fs) != 1 || fs[0].Resource != "k8s:prod/ns/Deployment/root" || fs[0].Factors.Score != 600 {
			t.Errorf("%+v", fs)
		}
	})
	t.Run("default-deny", func(t *testing.T) {
		inv := &model.Inventory{
			Workloads:       []*model.Workload{workload("a", false, model.True), workload("b", false, model.True)},
			NetworkPolicies: []*model.NetworkPolicy{{Cluster: "prod", Namespace: "ns", SelectsAll: true, Ingress: true}},
		}
		if fs := run(t, NoDefaultDenyNetPo, &rules.Input{Inventory: inv}); len(fs) != 0 {
			t.Errorf("a default-deny policy covers the namespace: %+v", fs)
		}
		inv.NetworkPolicies[0].IngressRules = 1
		if fs := run(t, NoDefaultDenyNetPo, &rules.Input{Inventory: inv}); len(fs) != 1 || fs[0].Resource != "k8s:prod//Namespace/ns" || fs[0].Factors.Score != 245 {
			t.Errorf("one finding per namespace, low: %+v", fs)
		}
	})
	t.Run("automount", func(t *testing.T) {
		inv := &model.Inventory{
			Workloads: []*model.Workload{workload("ci", false, model.True, model.DefaultAutomountToken), workload("off", false, model.False), workload("api", false, model.True)},
			RBAC: []*model.RBACGrant{
				{Cluster: "prod", SubjectKind: "ServiceAccount", SubjectNamespace: "ns", SubjectName: "ci", Rules: []model.RBACRule{{Verbs: []string{"get"}}}},
				{Cluster: "prod", SubjectKind: "ServiceAccount", SubjectNamespace: "ns", SubjectName: "off", Unresolved: "role missing"},
				{Cluster: "prod", SubjectKind: "User", SubjectName: "api"},
			},
		}
		fs := run(t, AutomountWithRBAC, &rules.Input{Inventory: inv})
		if len(fs) != 1 || fs[0].Resource != "k8s:prod/ns/Deployment/ci" || len(fs[0].DefaultsUsed) != 1 {
			t.Errorf("%+v", fs)
		}
	})
	t.Run("imds-and-rotation-and-public-access", func(t *testing.T) {
		key := func(arn string, rot model.Tri, d ...string) *model.Resource {
			return model.NewResource(&model.ResourceInput{Kind: model.KindKMSKey, ARN: arn, KeyRotation: rot, Defaulted: d})
		}
		bucket := model.NewResource(&model.ResourceInput{Kind: model.KindS3Bucket, ARN: "arn:aws:s3:::b", S3: model.S3Settings{RestrictPublicBuckets: model.False}})
		inv := &model.Inventory{
			NodeGroups: []*model.NodeGroup{{Cluster: "prod", Name: "v1", HTTPTokens: "optional"}, {Cluster: "prod", Name: "v2", HTTPTokens: "required"}, {Cluster: "prod", Name: "unknown"}},
			Resources:  []*model.Resource{key("k1", model.False, model.DefaultKeyRotationTF), key("k2", model.True), key("k3", model.Unknown), key("k4", model.False), bucket},
		}
		if fs := run(t, IMDSv1, &rules.Input{Inventory: inv}); len(fs) != 1 || fs[0].Resource != "eks-nodegroup:prod/v1" {
			t.Errorf("IMDS: %+v", fs)
		}
		fs := run(t, KeyRotationOff, &rules.Input{Inventory: inv})
		if len(fs) != 2 || len(fs[0].DefaultsUsed) != 1 || len(fs[1].DefaultsUsed) != 0 {
			t.Errorf("rotation: %+v", fs)
		}
		jewels := map[graph.NodeID]*model.Resource{0: bucket, 1: inv.Resources[0]}
		if fs := run(t, PublicAccessOff, &rules.Input{Inventory: inv, Jewels: jewels}); len(fs) != 1 || fs[0].Resource != "arn:aws:s3:::b" {
			t.Errorf("public access: %+v", fs)
		}
	})
}

func TestIRSATrustProbe(t *testing.T) {
	trust := func(cond string) *model.PolicyDocument {
		d, err := iampolicy.Parse([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::1:oidc-provider/oidc.example/id/X"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":`+cond+`}]}`),
			&iampolicy.Options{ID: "trust", Kind: model.PolicyResource})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	role := model.NewPrincipal(model.KindIAMRole, "arn:aws:iam::1:role/r", "1", &model.SourceLocation{})
	for cond, want := range map[string]int{
		`{"StringLike":{"oidc.example/id/X:sub":"system:serviceaccount:*:*"}}`:            1,
		`{"StringEquals":{"oidc.example/id/X:aud":"sts.amazonaws.com"}}`:                  1,
		`{"StringEquals":{"oidc.example/id/X:sub":"system:serviceaccount:payments:api"}}`: 0,
	} {
		inv := &model.Inventory{
			Principals: []*model.Principal{role},
			Trusts:     []*model.TrustRelationship{model.NewTrustRelationship(role.ID(), trust(cond))},
			Clusters:   []*model.Cluster{{Name: "nocfg"}, {Name: "prod", OIDCIssuer: "https://oidc.example/id/X"}},
		}
		if fs := run(t, IRSATrustAnySA, &rules.Input{Inventory: inv, Partition: "aws"}); len(fs) != want {
			t.Errorf("%s: %d findings, want %d", cond, len(fs), want)
		}
	}
}
