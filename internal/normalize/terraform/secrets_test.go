package terraform

import (
	"context"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/terraform/hclstatic"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/managedpolicies"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/normalize"
	"github.com/r3oof-900/clapa/internal/safeio"
)

func TestSecretsAndParameters(t *testing.T) {
	rec := &coverage.Recorder{}
	m, err := hclstatic.Collect(context.Background(), &collect.Input{Root: "testdata", Path: "secrets", Limits: safeio.DefaultLimits()}, rec)
	if err != nil {
		t.Fatal(err)
	}
	mp, _ := managedpolicies.Load()
	b := normalize.NewBuilder()
	Normalize(m, &Options{Account: "111122223333", Region: "us-east-1", Partition: "aws"}, mp, b, rec)
	inv, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	byKind := map[model.NodeKind][]*model.Resource{}
	for _, r := range inv.Resources {
		byKind[r.Kind()] = append(byKind[r.Kind()], r)
	}
	secrets, params := byKind[model.KindSecret], byKind[model.KindSSMParameter]
	if len(secrets) != 2 || len(params) != 2 {
		t.Fatalf("secrets %d params %d", len(secrets), len(params))
	}
	var db, plain *model.Resource
	for _, s := range secrets {
		if strings.Contains(s.ARN(), ":secret:prod/db-") {
			db = s
		} else {
			plain = s
		}
	}
	// The ARN's random suffix is not known before apply: unresolved.
	if db == nil || !model.ContainsUnresolved(db.ARN()) || db.Encryption().KeyARN != "arn:aws:kms:us-east-1:111122223333:key/tf-aws_kms_key.k" {
		t.Fatalf("db %+v %+v", db, db.Encryption())
	}
	if plain.Encryption().Type != "aws:kms" || plain.Encryption().KeyARN != "" {
		t.Fatalf("no kms_key_id: the AWS managed key: %+v", plain.Encryption())
	}
	policies := 0
	for _, p := range inv.Policies {
		if p.Target == db.ID() {
			policies++
		}
	}
	if policies != 1 {
		t.Fatalf("the secret policy is attached to db: %d", policies)
	}
	for _, p := range params {
		switch p.ARN() {
		case "arn:aws:ssm:us-east-1:111122223333:parameter/prod/db/password":
			if e := p.Encryption(); e.Type != "aws:kms" || e.KeyARN != "" {
				t.Errorf("SecureString without key_id: aws/ssm: %+v", e)
			}
		case "arn:aws:ssm:us-east-1:111122223333:parameter/prod/url":
			if p.Encryption().Type != "none" {
				t.Errorf("String: plaintext: %+v", p.Encryption())
			}
		default:
			t.Errorf("parameter %s", p.ARN())
		}
	}
}
