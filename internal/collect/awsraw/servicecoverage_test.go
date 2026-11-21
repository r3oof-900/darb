package awsraw

import (
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/coverage"
)

func TestServiceCoverage(t *testing.T) {
	ok, denied := StatusOK, StatusAccessDenied
	calls := []Call{
		{Service: "sts", API: "GetCallerIdentity", Status: ok},
		{Service: "iam", API: "GetAccountAuthorizationDetails", Status: ok},
		{Service: "kms", Region: "eu-west-1", API: "ListAliases", Status: denied},
		{Service: "kms", Region: "eu-west-1", API: "ListKeys", Status: ok},
		{Service: "kms", Region: "eu-west-1", API: "DescribeKey", Target: "k1", Status: ok},
		{Service: "kms", Region: "eu-west-1", API: "GetKeyPolicy", Target: "k1", Status: denied},
		{Service: "kms", Region: "eu-west-1", API: "DescribeKey", Target: "k2", Status: ok},
		{Service: "kms", Region: "us-east-1", API: "ListKeys", Status: StatusThrottling},
		{Service: "s3", API: "ListBuckets", Status: ok},
		{Service: "s3", Region: "eu-west-1", API: "GetBucketPolicy", Target: "a", Status: ok},
		{Service: "s3", Region: "us-east-1", API: "GetBucketPolicy", Target: "b", Status: ok},
		{Service: "eks", Region: "eu-west-1", API: "ListClusters", Status: ok},
		{Service: "eks", Region: "eu-west-1", API: "DescribeCluster", Target: "prod", Status: ok},
		{Service: "eks", Region: "eu-west-1", API: "DescribePodIdentityAssociation", Target: "prod/a-1", Status: StatusTimeout},
	}
	got := map[string]Coverage{}
	for _, c := range ServiceCoverage(calls) {
		got[c.Service+" "+c.Region] = c
	}
	for k, want := range map[string]struct {
		known           bool
		units, complete int
		full            bool
		text            string
	}{
		"iam ":          {true, 1, 1, true, "1 of 1"},
		"kms eu-west-1": {true, 2, 1, false, "1 of 2 keys"},
		"kms us-east-1": {false, 0, 0, false, "coverage unknown: kms:ListKeys failed (Throttling), so the number of keys is not known"},
		"s3 ":           {true, 2, 2, true, "2 of 2 buckets"},
		"eks eu-west-1": {true, 1, 0, false, "0 of 1 clusters"},
	} {
		c, ok := got[k]
		if !ok || c.Known != want.known || c.Units != want.units || c.Complete != want.complete || c.Full() != want.full || !strings.Contains(c.String(), want.text) {
			t.Errorf("%s: %+v %q", k, c, c.String())
		}
	}
	if len(got) != 5 {
		t.Fatalf("services %v", got)
	}
	// No list call at all: unknown, never complete.
	if c := ServiceCoverage([]Call{{Service: "ssm", Region: "x", API: "ListTagsForResource", Target: "p", Status: ok}}); c[0].Full() || !strings.Contains(c[0].String(), "was not made") {
		t.Fatalf("%+v", c)
	}
}

func TestCallGap(t *testing.T) {
	if (&Call{Status: StatusOK}).Gap("s", "a") != nil {
		t.Fatal("an ok call is no gap")
	}
	for status, kind := range map[string]coverage.Kind{
		StatusAccessDenied: coverage.KindAccessDenied, StatusThrottling: coverage.KindThrottled,
		StatusTimeout: coverage.KindTimeout, StatusError: coverage.KindAPIError, "Weird": coverage.KindAPIError,
	} {
		g := (&Call{Service: "kms", Region: "r", API: "GetKeyPolicy", Target: "k", Status: status, Error: "e"}).Gap("src", "111")
		if g.Kind != kind || g.Source != "src" || g.Account != "111" || g.Address != "k" || g.Detail != "e" || g.API != "GetKeyPolicy" {
			t.Errorf("%s: %+v", status, g)
		}
	}
}
