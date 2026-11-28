package awslive_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/r3oof-900/darb/internal/collect/awslive"
	"github.com/r3oof-900/darb/internal/collect/awslive/awsfake"
	"github.com/r3oof-900/darb/internal/collect/awsraw"
	"github.com/r3oof-900/darb/internal/coverage"
)

func collectWith(t *testing.T, ff *awsfake.Factory, wait time.Duration) (*awsraw.Account, []time.Duration) {
	t.Helper()
	var slept []time.Duration
	opts := &awslive.Options{
		Factory: ff, Regions: []string{"eu-west-1"}, CallTimeout: 50 * time.Millisecond, ReportWait: wait,
		Sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil },
	}
	snap, err := awslive.Collect(context.Background(), opts, &coverage.Recorder{})
	if err != nil {
		t.Fatal(err)
	}
	return snap.Accounts[0], slept
}

// GenerateCredentialReport is asynchronous: the collector polls with a
// doubling wait until the report is ready, then reads it, and lists each
// user's keys for their IDs.
func TestCredentialReportPolling(t *testing.T) {
	a, slept := collectWith(t, &awsfake.Factory{ReportPending: 2}, time.Minute)
	if !slices.Equal(slept, []time.Duration{time.Second, 2 * time.Second}) {
		t.Errorf("waits: %v", slept)
	}
	if a.CredentialReport == nil || a.CredentialReport.GeneratedTime != "2026-11-27T12:00:00Z" || len(a.CredentialReport.Rows) != 2 {
		t.Fatalf("report: %+v", a.CredentialReport)
	}
	if k := a.AccessKeys["deploy"]; len(k) != 1 || k[0].AccessKeyID != "AKIAEXAMPLEDEPLOY001" || k[0].Status != "Active" { //nolint:gosec // G101: the fake's example key ID, not a credential.
		t.Errorf("keys: %+v", a.AccessKeys)
	}
	if len(a.KeyLastUsed) != 0 {
		t.Errorf("with the report, no GetAccessKeyLastUsed: %v", a.KeyLastUsed)
	}
}

// A report that is not ready within ReportWait is a timeout (a gap), never
// a stop: the keys come from ListAccessKeys and their last use from
// GetAccessKeyLastUsed.
func TestCredentialReportTimeoutFallsBack(t *testing.T) {
	a, slept := collectWith(t, &awsfake.Factory{ReportPending: 100}, 3*time.Second)
	if a.CredentialReport != nil || len(slept) == 0 {
		t.Fatalf("report %+v, waits %v", a.CredentialReport, slept)
	}
	timedOut := slices.ContainsFunc(a.Calls, func(c awsraw.Call) bool {
		return c.API == "GetCredentialReport" && c.Status == awsraw.StatusTimeout
	})
	if !timedOut {
		t.Errorf("the wait is recorded as a timeout: %+v", a.Calls)
	}
	if a.KeyLastUsed["AKIAEXAMPLEDEPLOY001"] != "2026-11-01T00:00:00Z" || len(a.AccessKeys["deploy"]) != 1 {
		t.Errorf("fallback: keys %+v, last used %v", a.AccessKeys, a.KeyLastUsed)
	}
}
