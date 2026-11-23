package app

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/r3oof-900/darb/internal/access"
	"github.com/r3oof-900/darb/internal/collect/awslive"
	"github.com/r3oof-900/darb/internal/collect/awslive/awsfake"
	"github.com/r3oof-900/darb/internal/config"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/safeio"
)

// Live AWS scans run on the in-memory fake account (awsfake); no test
// reaches AWS.

func liveInputs(t *testing.T, f *awsfake.Factory) *Inputs {
	t.Helper()
	return &Inputs{
		Root: t.TempDir(), Config: config.Default(), Limits: safeio.DefaultLimits(),
		AWSLive: &AWSLive{Factory: f, Regions: []string{"eu-west-1"}},
	}
}

func notesOf(kind string, notes []access.Note) []access.Note {
	var out []access.Note
	for _, n := range notes {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

// The fake account's role has ReadOnlyAccess attached, which is not in the
// vendored managed-policy snapshot: the report says so, with the count and
// the name, and the console prints the warning.
func TestLiveScanReportsMissingManagedPolicies(t *testing.T) {
	in := liveInputs(t, &awsfake.Factory{})
	l, err := Load(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if l.Collected != 1 {
		t.Fatalf("collected %d", l.Collected)
	}
	mp := notesOf(NoteManagedPolicies, l.Notes)
	if len(mp) != 1 || mp[0].Subject != "1 AWS managed policies" ||
		!strings.HasPrefix(mp[0].Detail, "managed policy snapshot is incomplete: run tools/refresh-managed-policies.") ||
		!strings.HasSuffix(mp[0].Detail, ": ReadOnlyAccess") {
		t.Fatalf("notes %+v", l.Notes)
	}
	gapped := false
	for _, g := range l.Gaps {
		gapped = gapped || (g.Kind == coverage.KindNotModelled && g.Address == "arn:aws:iam::aws:policy/ReadOnlyAccess")
	}
	if !gapped {
		t.Fatalf("the unknown policy is also a gap: %+v", l.Gaps)
	}
	a, err := Analyze(l, in.Config, DefaultFailOn)
	if err != nil {
		t.Fatal(err)
	}
	var console, js bytes.Buffer
	if werr := Write(&console, "console", Report(a, in.Config, DefaultFailOn)); werr != nil {
		t.Fatal(werr)
	}
	if !strings.Contains(console.String(), "WARNING: managed policy snapshot is incomplete: run tools/refresh-managed-policies") ||
		!strings.Contains(console.String(), "ReadOnlyAccess") {
		t.Fatalf("console:\n%s", console.String())
	}
	if werr := Write(&js, "json", Report(a, in.Config, DefaultFailOn)); werr != nil {
		t.Fatal(werr)
	}
	sch, _ := reportSchema(t)
	doc, err := jsonschema.UnmarshalJSON(&js)
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(doc); err != nil {
		t.Fatalf("schema: %v", err)
	}
}

// A failed list call makes that service's coverage unknown, in a note the
// console prints; a failed detail call makes it partial.
func TestLiveScanServiceCoverage(t *testing.T) {
	f := &awsfake.Factory{Fail: map[string]error{
		"ListKeys":            awsfake.Denied("AccessDeniedException"),
		"GetBucketPolicy pii": awsfake.Denied("AccessDenied"),
	}}
	in := liveInputs(t, f)
	l, err := Load(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, n := range notesOf(NoteServiceCoverage, l.Notes) {
		got[n.Subject] = n.Detail
	}
	if !strings.Contains(got["111122223333 kms eu-west-1"], "coverage unknown: kms:ListKeys failed (AccessDenied)") ||
		!strings.Contains(got["111122223333 s3"], "1 of 2 buckets") || len(got) != 2 {
		t.Fatalf("coverage notes %v", got)
	}
	a, err := Analyze(l, in.Config, DefaultFailOn)
	if err != nil {
		t.Fatal(err)
	}
	if a.ExitCode != 3 {
		t.Fatalf("exit %d: an incomplete scan without findings is 3", a.ExitCode)
	}
	var console bytes.Buffer
	if err := Write(&console, "console", Report(a, in.Config, DefaultFailOn)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(console.String(), "WARNING: coverage of 111122223333 kms eu-west-1: coverage unknown") {
		t.Fatalf("console:\n%s", console.String())
	}
}

// A live scan and a scan of the snapshot collect-snapshot wrote from the
// same account give the same inventory, gaps and notes.
func TestCollectSnapshotThenScanMatchesLive(t *testing.T) {
	fail := map[string]error{"GetKeyPolicy k1": awsfake.Denied("AccessDeniedException")}
	live := liveInputs(t, &awsfake.Factory{Fail: fail})
	ll, err := Load(context.Background(), live)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	res, err := CollectSnapshot(context.Background(), &AWSLive{Factory: &awsfake.Factory{Fail: fail}, Regions: []string{"eu-west-1"}}, filepath.Join(root, "snap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 1 || len(res.Failed) != 1 || res.Calls < 20 {
		t.Fatalf("result %+v", res)
	}
	sl, err := Load(context.Background(), &Inputs{Root: root, Config: config.Default(), Limits: safeio.DefaultLimits(), AWSSnapshots: []string{"snap"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ll.Notes, sl.Notes) {
		t.Fatalf("notes\n live %+v\n snap %+v", ll.Notes, sl.Notes)
	}
	strip := func(gs []coverage.Gap) []coverage.Gap {
		out := make([]coverage.Gap, len(gs))
		for i, g := range gs {
			g.Source = ""
			out[i] = g
		}
		return out
	}
	if !reflect.DeepEqual(strip(ll.Gaps), strip(sl.Gaps)) {
		t.Fatalf("gaps\n live %+v\n snap %+v", ll.Gaps, sl.Gaps)
	}
	if len(ll.Inventory.Resources) != len(sl.Inventory.Resources) || len(ll.Inventory.Policies) != len(sl.Inventory.Policies) ||
		len(ll.Inventory.Principals) != len(sl.Inventory.Principals) {
		t.Fatalf("inventories differ: resources %d/%d policies %d/%d", len(ll.Inventory.Resources), len(sl.Inventory.Resources),
			len(ll.Inventory.Policies), len(sl.Inventory.Policies))
	}
}

func TestLiveScanNothingCollected(t *testing.T) {
	in := liveInputs(t, &awsfake.Factory{Fail: map[string]error{"GetCallerIdentity": awsfake.Denied("AccessDenied")}})
	if _, err := Load(context.Background(), in); !errors.Is(err, awslive.ErrNothingCollected) {
		t.Fatalf("err %v", err)
	}
}

// Phase 2 of the limits: a live scan lists every key's grants and reads
// every bucket's Object Ownership. A key whose grants were listed is not
// named in the KMS grants note; a failed ListGrants is a gap and names the
// key. logs has no ownership controls (ACLs enabled): a gap and the S3 ACLs
// note; pii is BucketOwnerEnforced: neither.
func TestLiveScanGrantsAndOwnership(t *testing.T) {
	analyze := func(f *awsfake.Factory) *Analysis {
		in := liveInputs(t, f)
		l, err := Load(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(l, in.Config, DefaultFailOn)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	note := func(a *Analysis, subject string) string {
		for _, n := range a.Notes {
			if n.Subject == subject {
				return n.Detail
			}
		}
		return ""
	}
	gaps := func(a *Analysis, text string) []string {
		var out []string
		for _, g := range a.Gaps {
			if strings.Contains(g.Detail, text) {
				out = append(out, g.Address)
			}
		}
		return out
	}
	const k1 = "arn:aws:kms:eu-west-1:111122223333:key/k1"
	a := analyze(&awsfake.Factory{})
	// The logs bucket (us-east-1) names a key k1 there, which is not in the
	// input: its grants are unknown. The collected k1 is not named.
	if kms := note(a, NoteKMSGrants); strings.Contains(kms, k1) || !strings.Contains(kms, "arn:aws:kms:us-east-1:111122223333:key/k1") {
		t.Errorf("grants listed, still named: %q", kms)
	}
	if s3 := note(a, NoteS3ACLs); !strings.Contains(s3, "arn:aws:s3:::logs") || strings.Contains(s3, "arn:aws:s3:::pii") {
		t.Errorf("S3 ACLs note: %q", s3)
	}
	if g := gaps(a, "ACLs are enabled (no ownership controls on an existing bucket)"); !reflect.DeepEqual(g, []string{"arn:aws:s3:::logs"}) {
		t.Errorf("ACL gaps: %v", g)
	}
	a = analyze(&awsfake.Factory{Fail: map[string]error{"ListGrants k1": awsfake.Denied("AccessDeniedException")}})
	if kms := note(a, NoteKMSGrants); !strings.Contains(kms, k1) || strings.Contains(kms, "key/aws1") {
		t.Errorf("failed ListGrants: %q", kms)
	}
	denied := false
	for _, g := range a.Gaps {
		denied = denied || g.Kind == coverage.KindAccessDenied && g.API == "ListGrants" && g.Address == "k1"
	}
	if !denied {
		t.Errorf("no access-denied gap for ListGrants k1: %+v", a.Gaps)
	}
}
