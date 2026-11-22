package terraform

import (
	"errors"
	"testing"

	"github.com/r3oof-900/darb/internal/collect/tfraw"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/managedpolicies"
	"github.com/r3oof-900/darb/internal/normalize"
)

// FuzzReservedText: whatever text the input holds (a policy document, a
// name, a tag key or value, template pieces around a reference), no
// placeholder the normalizer did not create reaches the inventory. If one
// did, Build would fail with ErrUnregisteredPlaceholder.
func FuzzReservedText(f *testing.F) {
	bs := string(rune(0x5c)) // a backslash, so the escapes stay escapes in this file
	for _, s := range []string{
		"${darb:unresolved:x}",
		"$" + bs + "u007bdarb:unresolved:x}",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"` + bs + `u0024{darb:unresolved:x}"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
		"${da", "rb:unresolved:", "%24%7Bdarb:unresolved:x%7D", "",
	} {
		f.Add(s, "rb:unresolved:")
	}
	mp, err := managedpolicies.Load()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, text, other string) {
		role := tfraw.NewObject()
		role.Set("name", tfraw.String(text))
		role.Set("assume_role_policy", tfraw.String(text))
		tags := tfraw.NewObject()
		tags.Set(text, tfraw.String(other))
		role.Set("tags", &tfraw.Value{Kind: tfraw.KObject, Obj: tags})
		bucket := tfraw.NewObject()
		bucket.Set("bucket", tfraw.String(other))
		policy := tfraw.NewObject()
		policy.Set("role", &tfraw.Value{Kind: tfraw.KRef, Ref: &tfraw.Ref{Address: "aws_iam_role.r", Attr: "id"}})
		policy.Set("policy", &tfraw.Value{Kind: tfraw.KTemplate, List: []*tfraw.Value{
			tfraw.String(text), {Kind: tfraw.KRef, Ref: &tfraw.Ref{Address: "aws_s3_bucket.b", Attr: "bucket"}}, tfraw.String(text),
		}})
		m := &tfraw.Module{Resources: []*tfraw.Resource{
			{Address: "aws_iam_role.r", Mode: "managed", Type: "aws_iam_role", Name: "r", Root: "f", Attrs: role},
			{Address: "aws_s3_bucket.b", Mode: "managed", Type: "aws_s3_bucket", Name: "b", Root: "f", Attrs: bucket},
			{Address: "aws_iam_role_policy.p", Mode: "managed", Type: "aws_iam_role_policy", Name: "p", Root: "f", Attrs: policy},
		}}
		b := normalize.NewBuilder()
		Normalize(m, &Options{Account: "111122223333", Region: "us-east-1"}, mp, b, &coverage.Recorder{})
		if _, err := b.Build(); errors.Is(err, normalize.ErrUnregisteredPlaceholder) {
			t.Fatalf("text %q / %q: %v", text, other, err)
		}
	})
}
