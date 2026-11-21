package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/collect/awslive"
	"github.com/r3oof-900/clapa/internal/collect/awslive/awsfake"
)

// fakeEnv connects to the in-memory account; it records the profile and
// regions it was asked for.
type fakeEnv struct {
	fake    *awsfake.Factory
	err     error
	profile string
	regions []string
}

func (e *fakeEnv) env() *Env {
	return &Env{AWS: func(_ context.Context, profile string, regions []string) (awslive.Factory, []string, error) {
		e.profile, e.regions = profile, regions
		if e.err != nil {
			return nil, nil, e.err
		}
		if len(regions) == 0 {
			regions = []string{"eu-west-1"} // "the profile's region"
		}
		return e.fake, regions, nil
	}}
}

func runEnv(t *testing.T, e *fakeEnv, args ...string) (code ExitCode, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = RunWith(context.Background(), args, &out, &errOut, e.env())
	return code, out.String(), errOut.String()
}

func TestScanLiveAWS(t *testing.T) {
	e := &fakeEnv{fake: &awsfake.Factory{}}
	code, out, errOut := runEnv(t, e, "scan", "--root", t.TempDir(), "--live-aws", "--aws-profile", "audit", "--aws-region", "eu-west-1", "--aws-region", "us-east-1")
	// ReadOnlyAccess is not in the managed policy snapshot: a gap, so 3.
	if code != ExitIncomplete || !strings.Contains(out, "WARNING: managed policy snapshot is incomplete: run tools/refresh-managed-policies") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if e.profile != "audit" || !slices.Equal(e.regions, []string{"eu-west-1", "us-east-1"}) {
		t.Fatalf("connected with profile %q regions %v", e.profile, e.regions)
	}
	if !slices.Contains(e.fake.Calls(), "us-east-1 ListKeys") {
		t.Fatalf("the second region was not collected: %v", e.fake.Calls())
	}
}

func TestCollectSnapshotThenScan(t *testing.T) {
	root := t.TempDir()
	e := &fakeEnv{fake: &awsfake.Factory{}}
	code, out, errOut := runEnv(t, e, "collect-snapshot", "--out", filepath.Join(root, "snap"))
	if code != ExitOK || !strings.Contains(out, "1 account(s) (111122223333)") || !strings.Contains(out, ", 0 failed") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	code, out, _ = runEnv(t, &fakeEnv{err: errors.New("must not connect")}, "scan", "--root", root, "--aws-snapshot", "snap")
	if code != ExitIncomplete || !strings.Contains(out, "WARNING: managed policy snapshot is incomplete") || !strings.Contains(out, "1 inputs collected") {
		t.Fatalf("scan of the snapshot: exit %d\n%s", code, out)
	}
	// The directory exists now: refused before connecting.
	e2 := &fakeEnv{fake: &awsfake.Factory{}}
	if code, _, errOut := runEnv(t, e2, "collect-snapshot", "--out", filepath.Join(root, "snap")); code != ExitUsage || !strings.Contains(errOut, "exists") || e2.fake.Calls() != nil {
		t.Fatalf("existing directory: exit %d %q, calls %v", code, errOut, e2.fake.Calls())
	}
}

func TestCollectSnapshotWithFailures(t *testing.T) {
	root := t.TempDir()
	e := &fakeEnv{fake: &awsfake.Factory{Fail: map[string]error{"GetKeyPolicy k1": awsfake.Denied("AccessDeniedException")}}}
	code, out, _ := runEnv(t, e, "collect-snapshot", "--out", filepath.Join(root, "snap"))
	if code != ExitIncomplete || !strings.Contains(out, "1 failed") || !strings.Contains(out, "access-denied 111122223333 kms:GetKeyPolicy k1") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	manifest, err := os.ReadFile(filepath.Join(root, "snap", "manifest.json")) //nolint:gosec // G304: the test's temporary directory.
	if err != nil || !strings.Contains(string(manifest), `"status": "AccessDenied"`) {
		t.Fatalf("manifest: %v\n%s", err, manifest)
	}
	// Nothing collected: no bundle.
	e = &fakeEnv{fake: &awsfake.Factory{Fail: map[string]error{"GetCallerIdentity": awsfake.Denied("AccessDenied")}}}
	if code, _, errOut := runEnv(t, e, "collect-snapshot", "--out", filepath.Join(root, "none")); code != ExitIncomplete || !strings.Contains(errOut, "no account could be collected") {
		t.Fatalf("nothing collected: exit %d %q", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(root, "none")); err == nil {
		t.Fatal("a bundle was written for nothing")
	}
}

func TestLiveUsageErrors(t *testing.T) {
	root := t.TempDir()
	for name, args := range map[string][]string{
		"no --out":            {"collect-snapshot"},
		"extra argument":      {"collect-snapshot", "--out", filepath.Join(root, "x"), "extra"},
		"zero concurrency":    {"scan", "--root", root, "--live-aws", "--aws-concurrency", "0"},
		"bad timeout":         {"collect-snapshot", "--out", filepath.Join(root, "y"), "--aws-call-timeout", "-1s"},
		"remediate live":      {"remediate", "--root", root, "--live-aws", "0000000000000000000000000000000000000000000000000000000000000000"},
		"old --snapshot flag": {"scan", "--root", root, "--snapshot", "s"},
	} {
		if code, _, _ := runEnv(t, &fakeEnv{fake: &awsfake.Factory{}}, args...); code != ExitUsage {
			t.Errorf("%s: exit %d", name, code)
		}
	}
	e := &fakeEnv{err: errors.New("failed to get shared config profile, nope")}
	if code, _, errOut := runEnv(t, e, "scan", "--root", root, "--live-aws", "--aws-profile", "nope"); code != ExitUsage || !strings.Contains(errOut, "shared config profile") {
		t.Fatalf("connection error: exit %d %q", code, errOut)
	}
}
