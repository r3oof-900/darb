package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"slices"
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

// A document that would add JSON of its own (`{}}, {"arn": ...`), or that
// is not an object, is refused naming its ARN, and no file is written.
func TestInjectedDocumentIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-policies.json")
	h := header{Format: format, Date: "2026-11-22", Partition: "aws", Source: source}
	for name, doc := range map[string]string{
		"injection":  `{}}, {"arn": "arn:aws:iam::aws:policy/Fake", "default_version_id": "v1", "document": {"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
		"two values": `{} {}`,
		"array":      `[{"Effect":"Allow"}]`,
		"string":     `"x"`,
		"empty":      ``,
	} {
		ps := []policy{
			{ARN: "arn:aws:iam::aws:policy/Good", DefaultVersionID: "v1", Document: []byte(`{"Version":"2012-10-17","Statement":[]}`)},
			{ARN: "arn:aws:iam::aws:policy/Bad", DefaultVersionID: "v2", Document: []byte(doc)},
		}
		_, err := writeSnapshot(path, h, ps)
		if err == nil || !strings.Contains(err.Error(), "policy arn:aws:iam::aws:policy/Bad: the document") {
			t.Errorf("%s: %v", name, err)
		}
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s: a file was written", name)
		}
	}
}

// The vendored snapshot (three policies) is written again byte for byte.
func TestCurrentSnapshotIsRewrittenIdentically(t *testing.T) {
	file := filepath.Join("..", "..", filepath.FromSlash(snapshotPath))
	data, err := os.ReadFile(file) //nolint:gosec // G304: the repository's own snapshot.
	if err != nil {
		t.Fatal(err)
	}
	var f snapshotFile
	if uerr := json.Unmarshal(data, &f); uerr != nil {
		t.Fatal(uerr)
	}
	var ps []policy
	for _, e := range f.Policies {
		ps = append(ps, policy{ARN: e.ARN, DefaultVersionID: e.DefaultVersionID, Document: e.Document})
	}
	slices.Reverse(ps) // the order of the input does not matter
	out, err := renderWith(header{Format: f.Format, Date: f.SnapshotDate, Partition: f.Partition, Source: f.Source}, ps)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 3 || !bytes.Equal(out, data) {
		t.Fatalf("%d policies; the rewrite differs:\n%s", len(ps), out)
	}
	empty, err := renderWith(header{Format: format, Date: "d", Partition: "aws", Source: "s"}, nil)
	if err != nil || !json.Valid(empty) || !strings.Contains(string(empty), "\"policies\": [\n  ]\n}") {
		t.Errorf("an empty snapshot: %v %q", err, empty)
	}
}
