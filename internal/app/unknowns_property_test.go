package app

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"pgregory.net/rapid"

	"github.com/r3oof-900/darb/internal/iampolicy"
	"github.com/r3oof-900/darb/internal/model"
)

// Attaching a policy whose document is unknown (an AWS managed policy
// missing from the snapshot: an unknown Allow, an unknown Deny, or both) to
// any role of any scenario never lowers a severity and never makes a
// problem disappear: severity is the worst case of every unknown
// (DESIGN.md 6.2, SCORING.md 1). A path problem is an (entry, jewel) pair,
// a posture problem a (rule, resource): an unknown allow may add a better
// path of another rule for the same pair (a direct path beside an
// escalation), which the pair reports, at a severity at least as high.
func TestUnknownsNeverLowerSeverity(t *testing.T) {
	variants := []string{
		"01_classic/vulnerable", "01_classic/key_outside_input", "01b_classic_intended/vulnerable", "04_wildcard_sub/vulnerable",
		"04b_create_pods_wildcard/vulnerable", "05_aud_only/vulnerable", "06_role_chain_cross_account/vulnerable",
		"07_passrole_lambda/vulnerable", "08_rbac_create_pods/vulnerable", "09_hostnetwork_imds/vulnerable",
		"10_kms_principal_org_id/vulnerable", "12_public_bucket/vulnerable", "14_same_names_two_accounts/vulnerable",
		"17_pod_identity_classic/vulnerable", "18_same_cluster_name_two_regions/vulnerable", "19_secrets_manager/vulnerable",
		"20_ssm_securestring/vulnerable", "21_k8s_secret/vulnerable",
	}
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	dirs := map[string]string{}
	for _, v := range variants {
		dirs[v] = copyTree(t, filepath.Join(repoRoot(t), "tests", "fixtures", filepath.FromSlash(v)))
	}
	checked := 0
	rapid.Check(t, func(rt *rapid.T) {
		variant := rapid.SampledFrom(variants).Draw(rt, "scenario")
		in := scansFor(t, dirs[variant])["normalized.golden.json"]
		base := analyzeInputs(rt, in, nil)
		var roles []*model.Principal
		l, err := Load(context.Background(), in)
		if err != nil {
			rt.Fatal(err)
		}
		for _, p := range l.Inventory.Principals {
			if p.Kind() == model.KindIAMRole {
				roles = append(roles, p)
			}
		}
		if len(roles) == 0 {
			rt.Skip("no role")
		}
		role := rapid.SampledFrom(roles).Draw(rt, "role")
		kind := rapid.SampledFrom([]string{"allow", "deny", "both"}).Draw(rt, "unknown policy")
		after := analyzeInputs(rt, in, func(l *Loaded) {
			l.Inventory.Policies = append(l.Inventory.Policies, &model.AttachedPolicy{Target: role.ID(), Doc: unknownPolicy(rt, kind)})
		})
		for fp, sev := range base {
			got, ok := after[fp]
			if !ok {
				rt.Fatalf("%s: an unknown %s policy on %s removed %s", variant, kind, role.Identity(), fp)
			}
			if rank[got] < rank[sev] {
				rt.Fatalf("%s: an unknown %s policy on %s lowered %s from %s to %s", variant, kind, role.Identity(), fp, sev, got)
			}
		}
		checked++
	})
	if checked == 0 {
		t.Fatal("no case was checked")
	}
}

// analyzeInputs returns the highest severity of every problem (a path
// finding's entry and jewel, a posture finding's rule and resource), after
// edit changes the loaded inventory.
func analyzeInputs(t *rapid.T, in *Inputs, edit func(*Loaded)) map[string]string {
	l, err := Load(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(l)
	}
	a, err := Analyze(l, in.Config, DefaultFailOn)
	if err != nil {
		t.Fatal(err)
	}
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	out := map[string]string{}
	for i := range a.Findings {
		f := &a.Findings[i]
		key := f.Entry + " -> " + f.Jewel
		if f.Resource != "" {
			key = f.Rule + " " + f.Resource
		}
		if old, ok := out[key]; !ok || rank[f.Factors.Severity] > rank[old] {
			out[key] = f.Factors.Severity
		}
	}
	return out
}

// unknownPolicy is an identity policy whose statements are unknown, as the
// AWS normalizer writes for a managed policy missing from the snapshot.
func unknownPolicy(t *rapid.T, kind string) *model.PolicyDocument {
	p := model.UnresolvedPlaceholder("unknown_managed_policy")
	var stmts []any
	if kind != "deny" {
		stmts = append(stmts, map[string]any{"Effect": "Allow", "Action": p, "Resource": p})
	}
	if kind != "allow" {
		stmts = append(stmts, map[string]any{"Effect": "Deny", "Action": p, "Resource": "*"})
	}
	js, err := json.Marshal(map[string]any{"Version": model.Version2012, "Statement": stmts})
	if err != nil {
		t.Fatal(err)
	}
	d, err := iampolicy.Parse(js, &iampolicy.Options{ID: "arn:aws:iam::aws:policy/UnknownToTheSnapshot", Kind: model.PolicyIdentity, Placeholders: true})
	if err != nil {
		t.Fatal(err)
	}
	return d
}
