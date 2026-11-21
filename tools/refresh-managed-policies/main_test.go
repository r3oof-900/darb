package main

import (
	"bytes"
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// fake is IAM with two pages of AWS managed policies. It records every
// call: the command may make only these two kinds.
type fake struct {
	pages [][]types.Policy
	docs  map[string]string // ARN@version -> document
	calls []string
}

func (f *fake) ListPolicies(_ context.Context, in *iam.ListPoliciesInput, _ ...func(*iam.Options)) (*iam.ListPoliciesOutput, error) {
	f.calls = append(f.calls, "ListPolicies scope="+string(in.Scope))
	page := 0
	if in.Marker != nil {
		page = 1
	}
	out := &iam.ListPoliciesOutput{Policies: f.pages[page]}
	if page == 0 {
		out.IsTruncated, out.Marker = true, aws.String("next")
	}
	return out, nil
}

func (f *fake) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	key := aws.ToString(in.PolicyArn) + "@" + aws.ToString(in.VersionId)
	f.calls = append(f.calls, "GetPolicyVersion "+key)
	return &iam.GetPolicyVersionOutput{PolicyVersion: &types.PolicyVersion{Document: aws.String(url.PathEscape(f.docs[key]))}}, nil
}

func listed(name, version string) types.Policy {
	return types.Policy{Arn: aws.String("arn:aws:iam::aws:policy/" + name), DefaultVersionId: aws.String(version)}
}

func newFake(order bool) *fake {
	a, b := listed("Zeta", "v3"), listed("Alpha", "v1")
	pages := [][]types.Policy{{a}, {b}}
	if order {
		pages = [][]types.Policy{{b}, {a}}
	}
	return &fake{pages: pages, docs: map[string]string{
		"arn:aws:iam::aws:policy/Zeta@v3": `{"Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*", "Condition": {"StringLike": {"aws:userid": "a+b c"}}}]}`,
		"arn:aws:iam::aws:policy/Alpha@v1": `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}`,
	}}
}

func TestCollectAndRender(t *testing.T) {
	f := newFake(false)
	ps, err := collect(context.Background(), f, "aws")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ListPolicies scope=AWS", "ListPolicies scope=AWS",
		"GetPolicyVersion arn:aws:iam::aws:policy/Zeta@v3", "GetPolicyVersion arn:aws:iam::aws:policy/Alpha@v1",
	}
	if strings.Join(f.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls: %v", f.calls)
	}
	out, err := render(ps, "2026-11-21", "aws")
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, s := range []string{
		`"policy_count": 2,`, `"partition": "aws",`, `"snapshot_date": "2026-11-21",`,
		`"default_version_id": "v3"`, `"aws:userid":"a+b c"`, // "+" kept, the document compact
	} {
		if !strings.Contains(text, s) {
			t.Errorf("missing %s in%s%s", s, string(rune(10)), text)
		}
	}
	if strings.Index(text, "Alpha") > strings.Index(text, "Zeta") {
		t.Error("policies are sorted by ARN")
	}
	// Deterministic: the other listing order gives the same bytes.
	again, err := collect(context.Background(), newFake(true), "aws")
	if err != nil {
		t.Fatal(err)
	}
	if out2, _ := render(again, "2026-11-21", "aws"); !bytes.Equal(out, out2) {
		t.Fatal("the same policies in another order give other bytes")
	}
}

func TestCollectRefusesOtherPolicies(t *testing.T) {
	f := newFake(false)
	f.pages[0] = []types.Policy{{Arn: aws.String("arn:aws:iam::111122223333:policy/mine"), DefaultVersionId: aws.String("v1")}}
	if _, err := collect(context.Background(), f, "aws"); err == nil {
		t.Fatal("a customer managed policy must be refused")
	}
	if _, err := render([]policy{{ARN: "a"}, {ARN: "a"}}, "d", "aws"); err == nil {
		t.Fatal("a duplicate must be refused")
	}
	if _, err := decode("%zz"); err == nil {
		t.Fatal("bad escapes must be refused")
	}
	if _, err := decode("not json"); err == nil {
		t.Fatal("a document that is not JSON must be refused")
	}
}
