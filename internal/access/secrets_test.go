package access

import (
	"slices"
	"testing"

	"github.com/r3oof-900/clapa/internal/model"
)

func TestParameterPaths(t *testing.T) {
	j := model.NewResource(&model.ResourceInput{Kind: model.KindSSMParameter, ARN: "arn:aws:ssm:us-east-1:1:parameter/prod/db/password"})
	want := []string{
		"arn:aws:ssm:us-east-1:1:parameter/prod/db/password", "arn:aws:ssm:us-east-1:1:parameter/prod/db",
		"arn:aws:ssm:us-east-1:1:parameter/prod", "arn:aws:ssm:us-east-1:1:parameter/",
	}
	if got := parameterPaths(j); !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
	flat := model.NewResource(&model.ResourceInput{Kind: model.KindSSMParameter, ARN: "arn:aws:ssm:us-east-1:1:parameter/flat"})
	if got := parameterPaths(flat); !slices.Equal(got, []string{"arn:aws:ssm:us-east-1:1:parameter/flat", "arn:aws:ssm:us-east-1:1:parameter/"}) {
		t.Fatalf("%v", got)
	}
}

func TestReadsSecret(t *testing.T) {
	rule := func(groups, resources, verbs, names []string) []model.RBACRule {
		return []model.RBACRule{{APIGroups: groups, Resources: resources, Verbs: verbs, ResourceNames: names}}
	}
	core, secrets := []string{""}, []string{"secrets"}
	for name, c := range map[string]struct {
		rules []model.RBACRule
		want  bool
	}{
		"get":               {rule(core, secrets, []string{"get"}, nil), true},
		"list returns data": {rule(core, secrets, []string{"list"}, nil), true},
		"watch":             {rule(core, secrets, []string{"watch"}, nil), true},
		"wildcards":         {rule([]string{"*"}, []string{"*"}, []string{"*"}, nil), true},
		"this name":         {rule(core, secrets, []string{"get"}, []string{"db"}), true},
		"another name":      {rule(core, secrets, []string{"get"}, []string{"other"}), false},
		"create only":       {rule(core, secrets, []string{"create"}, nil), false},
		"configmaps":        {rule(core, []string{"configmaps"}, []string{"get"}, nil), false},
		"another group":     {rule([]string{"apps"}, secrets, []string{"get"}, nil), false},
	} {
		if got := readsSecret(c.rules, "db"); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestSplitSecretIdentity(t *testing.T) {
	for id, want := range map[string][3]string{
		"k8s:prod/payments/Secret/db":                                            {"prod", "payments", "db"},
		"k8s:arn:aws:eks:us-east-1:111122223333:cluster/prod/payments/Secret/db": {"arn:aws:eks:us-east-1:111122223333:cluster/prod", "payments", "db"},
	} {
		c, ns, n, ok := splitSecretIdentity(id)
		if !ok || c != want[0] || ns != want[1] || n != want[2] {
			t.Errorf("%s: %q %q %q %v", id, c, ns, n, ok)
		}
	}
	for _, bad := range []string{"arn:aws:s3:::x", "k8s:prod/payments/Deployment/api", "k8s:Secret/x"} {
		if _, _, _, ok := splitSecretIdentity(bad); ok {
			t.Errorf("%s accepted", bad)
		}
	}
}
