package awssnapshot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/collect"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/safeio"
)

func TestCollectSnapshot(t *testing.T) {
	rec := &coverage.Recorder{}
	snap, err := Collect(context.Background(), &collect.Input{Root: "testdata", Path: "snap", Limits: safeio.DefaultLimits()}, rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Accounts) != 1 {
		t.Fatalf("accounts %d", len(snap.Accounts))
	}
	a := snap.Accounts[0]
	role := a.Auth.RoleDetailList[0]
	if role.Arn != "arn:aws:iam::111122223333:role/app" || len(role.AttachedManagedPolicies) != 1 ||
		role.PermissionsBoundary.PermissionsBoundaryArn == "" || !strings.Contains(string(role.AssumeRolePolicyDocument), "sts:AssumeRole") {
		t.Errorf("role %+v", role)
	}
	b := a.Buckets[0]
	if b.Name != "pii-data" || b.Region != "us-east-1" || b.Encryption.SSEAlgorithm != "aws:kms" || b.PublicAccessBlock.RestrictPublicBuckets ||
		b.Tags[0].Value != "pii" || !strings.Contains(b.Policy, "2012-10-17") {
		t.Errorf("bucket %+v", b)
	}
	k := a.Keys[0]
	if k.Metadata.Arn == "" || k.Region != "us-east-1" || k.RotationEnabled == nil || *k.RotationEnabled || k.Policy == "" {
		t.Errorf("key %+v", k)
	}
	c := a.Clusters[0]
	if c.OIDCIssuer == "" || len(c.PodIdentity) != 1 || c.PodIdentity[0].RoleArn == "" {
		t.Errorf("cluster %+v", c)
	}
	if len(a.Calls) != 4 {
		t.Errorf("calls %d", len(a.Calls))
	}
	want := map[coverage.Kind]int{
		coverage.KindAccessDenied: 1, coverage.KindThrottled: 1, coverage.KindAPIError: 1,
		coverage.KindUnsupported: 1, coverage.KindParseError: 1,
	}
	for kind, n := range want {
		if rec.Count(kind) != n {
			t.Errorf("%s gaps: %d, want %d\n%+v", kind, rec.Count(kind), n, rec.Gaps())
		}
	}
}

func TestRejectsNonSnapshot(t *testing.T) {
	root := t.TempDir()
	in := &collect.Input{Root: root, Path: ".", Limits: safeio.DefaultLimits()}
	if _, err := Collect(context.Background(), in, &coverage.Recorder{}); !errors.Is(err, ErrFormat) {
		t.Fatalf("missing manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(`{"format": "other/v9"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Collect(context.Background(), in, &coverage.Recorder{}); !errors.Is(err, ErrFormat) {
		t.Fatalf("wrong format: %v", err)
	}
}
