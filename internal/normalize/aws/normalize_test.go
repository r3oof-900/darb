package aws

import (
	"context"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/awssnapshot"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/managedpolicies"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/normalize"
	"github.com/r3oof-900/clapa/internal/safeio"
)

func TestNormalizeSnapshot(t *testing.T) {
	rec := &coverage.Recorder{}
	snap, err := awssnapshot.Collect(context.Background(), &collect.Input{Root: "testdata", Path: "snap", Limits: safeio.DefaultLimits()}, rec)
	if err != nil {
		t.Fatal(err)
	}
	mp, err := managedpolicies.Load()
	if err != nil {
		t.Fatal(err)
	}
	b := normalize.NewBuilder()
	Normalize(snap, mp, b, rec)
	inv, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	role := model.NewID(model.KindIAMRole, "arn:aws:iam::111122223333:role/app")
	docs := map[string]string{}
	for _, p := range append(append([]*model.AttachedPolicy{}, inv.Policies...), inv.Boundaries...) {
		if p.Target == role {
			docs[p.Doc.ID()+"|"+p.Doc.Kind().String()] = summary(p.Doc)
		}
	}
	for key, want := range map[string]string{
		"arn:aws:iam::111122223333:role/app#inline/cli-object|identity":  "Allow s3:GetObject",
		"arn:aws:iam::111122223333:role/app#inline/json-string|identity": "Allow kms:Decrypt",
		"arn:aws:iam::111122223333:role/app#inline/broken|identity":      "${clapa:unresolved:",
		"arn:aws:iam::111122223333:role/app#inline/bad-escape|identity":  "${clapa:unresolved:",
		"arn:aws:iam::111122223333:role/app#inline/missing|identity":     "${clapa:unresolved:",
		"arn:aws:iam::aws:policy/AmazonS3FullAccess|identity":            "Allow s3:*",
		"arn:aws:iam::aws:policy/NotInTheSnapshot|identity":              "${clapa:unresolved:",
		"arn:aws:iam::111122223333:policy/custom|identity":               "Allow sqs:*", // the default version, not v1
		"arn:aws:iam::111122223333:policy/custom|boundary":               "Allow sqs:*",
	} {
		if !strings.Contains(docs[key], want) {
			t.Errorf("%s: %q, want %q", key, docs[key], want)
		}
	}
	trust := inv.Trusts[0].Policy()
	if !strings.Contains(summary(trust), "sts:AssumeRole") {
		t.Errorf("URL-encoded trust policy: %s", summary(trust))
	}
	if len(inv.Resources) != 2 || len(inv.Clusters) != 1 || inv.Clusters[0].OIDCIssuer == "" || len(inv.PodIdentity) != 1 {
		t.Fatalf("resources %d clusters %+v pod identity %+v", len(inv.Resources), inv.Clusters, inv.PodIdentity)
	}
	for _, r := range inv.Resources {
		if r.Kind() == model.KindS3Bucket && (r.Encryption().Type != "" || r.S3().RestrictPublicBuckets != model.Unknown || r.Region() != "eu-west-1") {
			t.Errorf("uncollected facts stay unknown: %+v %+v", r.Encryption(), r.S3())
		}
	}
	gaps := gapText(rec)
	for _, want := range []string{"IAM users and groups are not yet analysed", "no IAM authorization details", "not available; treated as unknown"} {
		if !strings.Contains(gaps, want) {
			t.Errorf("missing gap %q in\n%s", want, gaps)
		}
	}
}

func summary(d *model.PolicyDocument) string {
	var b strings.Builder
	for _, s := range d.Statements() {
		a, _ := s.Actions()
		b.WriteString(s.Effect().String() + " " + strings.Join(a, ",") + ";")
	}
	return b.String()
}

func gapText(rec *coverage.Recorder) string {
	var b strings.Builder
	all := rec.Gaps()
	for i := range all {
		b.WriteString(all[i].Detail + "\n")
	}
	return b.String()
}
