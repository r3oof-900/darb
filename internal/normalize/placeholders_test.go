package normalize

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/model"
)

func TestOnlyRegisteredPlaceholders(t *testing.T) {
	src := model.FileLocation("main.tf", 1, 1, "x")
	b := NewBuilder()
	b.AddResource(model.NewResource(&model.ResourceInput{Kind: model.KindS3Bucket, ARN: "arn:aws:s3:::" + b.Placeholder("var.name"), Source: src}))
	if _, err := b.Build(); err != nil {
		t.Fatalf("a registered placeholder: %v", err)
	}
	b = NewBuilder()
	b.Placeholder("var.name")
	b.AddResource(model.NewResource(&model.ResourceInput{Kind: model.KindS3Bucket, ARN: "arn:aws:s3:::" + model.UnresolvedPlaceholder("forged"), Source: src}))
	_, err := b.Build()
	if !errors.Is(err, ErrUnregisteredPlaceholder) || !strings.Contains(err.Error(), "forged") {
		t.Fatalf("an unregistered placeholder must fail the build: %v", err)
	}
}

// Every string field of the plain inventory structs is checked: set to an
// unregistered placeholder, each one fails the build. A new field that
// inventoryStrings does not read fails this test.
func TestInventoryStringsComplete(t *testing.T) {
	skip := map[string]bool{"ID": true, "Source": true, "Unresolved": true} // identity hash, location, explanation
	forged := model.UnresolvedPlaceholder("forged")
	structs := []any{
		&model.ServiceAccount{}, &model.Cluster{}, &model.PodIdentityAssociation{}, &model.ClusterAddon{},
		&model.NodeGroup{}, &model.RBACGrant{}, &model.IdentityMapping{},
	}
	for _, s := range structs {
		typ := reflect.TypeOf(s).Elem()
		for i := range typ.NumField() {
			f := typ.Field(i)
			if skip[f.Name] {
				continue
			}
			v := reflect.New(typ)
			switch {
			case f.Type.Kind() == reflect.String:
				v.Elem().Field(i).SetString(forged)
			case f.Type == reflect.TypeFor[[]string]():
				v.Elem().Field(i).Set(reflect.ValueOf([]string{forged}))
			case f.Type == reflect.TypeFor[[]model.RBACRule]():
				v.Elem().Field(i).Set(reflect.ValueOf([]model.RBACRule{{APIGroups: []string{forged}}}))
			default:
				continue // Tri, int, bool: no text
			}
			b := NewBuilder()
			add(b, v.Interface())
			if _, err := b.Build(); !errors.Is(err, ErrUnregisteredPlaceholder) {
				t.Errorf("%s.%s is not checked for placeholders", typ.Name(), f.Name)
			}
		}
	}
	// RBAC rule fields beyond APIGroups.
	for _, r := range []model.RBACRule{{Resources: []string{forged}}, {Verbs: []string{forged}}, {ResourceNames: []string{forged}}} {
		b := NewBuilder()
		b.AddRBAC(&model.RBACGrant{Rules: []model.RBACRule{r}})
		if _, err := b.Build(); !errors.Is(err, ErrUnregisteredPlaceholder) {
			t.Errorf("RBAC rule %+v is not checked", r)
		}
	}
}

func add(b *Builder, v any) {
	switch x := v.(type) {
	case *model.ServiceAccount:
		b.AddServiceAccount(x)
	case *model.Cluster:
		x.Name += "c" // clusters are keyed by name
		b.AddCluster(x)
	case *model.PodIdentityAssociation:
		b.AddPodIdentity(x)
	case *model.ClusterAddon:
		b.AddAddon(x)
	case *model.NodeGroup:
		b.AddNodeGroup(x)
	case *model.RBACGrant:
		b.AddRBAC(x)
	case *model.IdentityMapping:
		b.AddMapping(x)
	}
}

// Node and policy strings read through getters.
func TestNodeAndPolicyStringsChecked(t *testing.T) {
	forged := model.UnresolvedPlaceholder("forged")
	src := model.FileLocation("f", 1, 1, "")
	docWith := func(st *model.StatementInput) *model.PolicyDocument {
		d, err := model.NewPolicyDocument(&model.PolicyInput{ID: "p", Kind: model.PolicyResource, Statements: []*model.StatementInput{st}})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	p := model.NewPrincipalSpec(false, []model.PrincipalRef{{Type: model.PrincipalAWS, Value: forged}})
	role := model.NewPrincipal(model.KindIAMRole, "arn:aws:iam::1:role/r", "1", &src)
	cases := map[string]func(b *Builder){
		"principal": func(b *Builder) {
			b.AddPrincipal(model.NewPrincipal(model.KindIAMRole, "arn:aws:iam::1:role/"+forged, "1", &src))
		},
		"tag": func(b *Builder) {
			b.AddResource(model.NewResource(&model.ResourceInput{Kind: model.KindS3Bucket, ARN: "arn:aws:s3:::b", Tags: map[string]string{"k": forged}, Source: src}))
		},
		"encryption key": func(b *Builder) {
			b.AddResource(model.NewResource(&model.ResourceInput{Kind: model.KindS3Bucket, ARN: "arn:aws:s3:::b", Encryption: model.Encryption{KeyARN: forged}, Source: src}))
		},
		"workload": func(b *Builder) {
			b.AddWorkload(model.NewWorkload(&model.WorkloadInput{Cluster: "c", Namespace: "n", Kind: "Pod", Name: "p", ServiceAccount: forged, Source: src}))
		},
		"trust principal": func(b *Builder) {
			b.AddTrust(model.NewTrustRelationship(role.ID(), docWith(&model.StatementInput{Effect: model.EffectAllow, Action: []string{"sts:AssumeRole"}, Principal: p})))
		},
		"boundary condition": func(b *Builder) {
			b.AddBoundary(&model.AttachedPolicy{Target: role.ID(), Doc: docWith(&model.StatementInput{
				Effect: model.EffectAllow, Action: []string{"*"}, Principal: model.NewPrincipalSpec(true, nil),
				Conditions: []model.Condition{model.NewCondition("StringEquals", "k", []string{forged})},
			})})
		},
		"policy resource": func(b *Builder) {
			b.AddPolicy(&model.AttachedPolicy{Target: role.ID(), Doc: docWith(&model.StatementInput{
				Effect: model.EffectAllow, Action: []string{"*"}, Resource: []string{forged}, Principal: model.NewPrincipalSpec(true, nil),
			})})
		},
	}
	for name, fill := range cases {
		b := NewBuilder()
		fill(b)
		if _, err := b.Build(); !errors.Is(err, ErrUnregisteredPlaceholder) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
