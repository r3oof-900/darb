package access

import (
	"testing"

	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/model"
)

// NODE_ROLE (DESIGN.md §7.2): hostNetwork reaches IMDS whatever the token
// setting; IMDSv1 or a hop limit >= 2 lets any pod reach it.
func TestIMDSReachable(t *testing.T) {
	cases := []struct {
		host     bool
		endpoint string
		tokens   string
		hops     int
		want     model.Tri
	}{
		{false, "enabled", "optional", 1, model.True},
		{false, "enabled", "required", 2, model.True},
		{false, "enabled", "required", 1, model.False},
		{true, "enabled", "required", 1, model.True},
		{true, "disabled", "optional", 2, model.False},
		{false, "", "", 0, model.Unknown},
		{true, "enabled", "", 0, model.True},
		{false, "enabled", "required", 0, model.Unknown},
	}
	for _, c := range cases {
		ng := &model.NodeGroup{HTTPEndpoint: c.endpoint, HTTPTokens: c.tokens, HopLimit: c.hops}
		if got := imdsReachable(c.host, ng); got != c.want {
			t.Errorf("%+v: %s, want %s", c, got, c.want)
		}
	}
}

func TestVerdictCombinators(t *testing.T) {
	a, d, i, u := eval.Allow, eval.Deny, eval.ImplicitDeny, eval.Unknown
	for _, c := range []struct{ x, y, want eval.Verdict }{
		{a, i, a}, {u, i, u}, {d, d, d}, {d, i, i}, {i, i, i},
	} {
		if got := either(c.x, c.y); got != c.want {
			t.Errorf("either(%s, %s) = %s", c.x, c.y, got)
		}
	}
	for _, c := range []struct {
		v        eval.Verdict
		restrict model.Tri
		want     eval.Verdict
	}{
		{a, model.False, a}, {a, model.True, i}, {a, model.Unknown, u}, {i, model.Unknown, i},
	} {
		if got := publicAccess(c.v, c.restrict); got != c.want {
			t.Errorf("publicAccess(%s, %s) = %s", c.v, c.restrict, got)
		}
	}
	rule := func(groups, resources, verbs []string, names ...string) []model.RBACRule {
		return []model.RBACRule{{APIGroups: groups, Resources: resources, Verbs: verbs, ResourceNames: names}}
	}
	core, all := []string{""}, []string{"*"}
	for _, c := range []struct {
		rules []model.RBACRule
		want  bool
	}{
		{rule(core, []string{"pods"}, []string{"create"}), true},
		{rule(core, []string{"pods"}, []string{"get"}), false},
		{rule(all, all, all, "one"), false},
		{rule(all, []string{"pods/exec"}, all), true},
		{rule(core, []string{"serviceaccounts/token"}, []string{"create"}), true},
		{rule(core, []string{"serviceaccounts"}, []string{"impersonate"}), true},
		{rule(core, []string{"serviceaccounts"}, []string{"create"}), false},
		{rule([]string{"apps"}, []string{"pods"}, []string{"create"}), false},
	} {
		if got := controlsServiceAccounts(c.rules); got != c.want {
			t.Errorf("%+v: %v", c.rules, got)
		}
	}
}
