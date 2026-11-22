package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseFull(t *testing.T) {
	c, err := Parse([]byte(`
version: 1
terraform: {account: "111122223333", region: us-east-1}
clusters:
  - {name: prod, account: "111122223333", region: us-east-1, oidc_issuer: "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"}
crown_jewels: {tag_keys: [DataClass], tag_values: [pii], explicit: [{arn: "arn:aws:s3:::b", classification: pci}]}
threat_model: {assume_compromised: false}
assume: {"aws:PrincipalOrgID": ["o-abc"]}
intended_access: [{principal: "k8s:prod/payments/Deployment/api", action: "s3:GetObject", resource: "arn:aws:s3:::payments/*"}]
remediation:
  cut_costs: {ASSUMES: 7}
  uncuttable_edges: [{kind: ASSUMES, from: a, to: b, reason: identity}]
coverage: {tolerance: {unresolved: 2}}
`))
	if err != nil {
		t.Fatal(err)
	}
	cl, ok := c.Cluster("prod")
	if !ok || cl.OIDCIssuer == "" || *c.ThreatModel.AssumeCompromised || c.Remediation.CutCosts["ASSUMES"] != 7 ||
		c.Terraform.Partition != "aws" || len(c.IntendedAccess) != 1 || c.Assume["aws:PrincipalOrgID"][0] != "o-abc" {
		t.Fatalf("got %+v", c)
	}
	if _, ok := c.Cluster("other"); ok {
		t.Error("unknown cluster")
	}
}

func TestParseDefaults(t *testing.T) {
	c, err := Parse([]byte("version: 1\n"))
	if err != nil || !*c.ThreatModel.AssumeCompromised || c.CrownJewels.TagKeys[0] != "DataClass" {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	if c.CrownJewels.IgnoreUnclassified() {
		t.Fatal("unclassified data stores are jewels by default")
	}
	// Setting crown_jewels.unclassified keeps the default tag keys and values.
	c, err = Parse([]byte("version: 1\ncrown_jewels: {unclassified: ignore}\n"))
	if err != nil || !c.CrownJewels.IgnoreUnclassified() || c.CrownJewels.TagKeys[0] != "DataClass" || len(c.CrownJewels.TagValues) != 4 {
		t.Fatalf("unclassified: ignore: %+v %v", c.CrownJewels, err)
	}
	c, err = Parse([]byte("version: 1\nthreat_model: {}\n"))
	if err != nil || !*c.ThreatModel.AssumeCompromised {
		t.Fatalf("assume_compromised must default to true: %v", err)
	}
}

// Two clusters of one name are distinct when their accounts or regions
// differ: their keys are their ARNs.
func TestClustersOfOneName(t *testing.T) {
	c, err := Parse([]byte("version: 1\nclusters: [{name: prod, account: '111122223333', region: eu-west-1}, {name: prod, account: '111122223333', region: us-east-1}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Clusters[0].Key("") != "arn:aws:eks:eu-west-1:111122223333:cluster/prod" || c.Clusters[1].Key("aws") != "arn:aws:eks:us-east-1:111122223333:cluster/prod" {
		t.Fatalf("keys %q %q", c.Clusters[0].Key(""), c.Clusters[1].Key(""))
	}
	if (&Cluster{Name: "x"}).Key("") != "x" {
		t.Fatal("without account and region the key is the name")
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":        "version: 1\nthreatmodel: {}\n",
		"bad version":          "version: 2\n",
		"bad account":          "version: 1\nterraform: {account: '123'}\n",
		"cluster no name":      "version: 1\nclusters: [{account: '111122223333'}]\n",
		"cluster dup":          "version: 1\nclusters: [{name: a}, {name: a}]\n",
		"cluster dup key":      "version: 1\nclusters: [{name: a, account: '111122223333', region: eu-west-1}, {name: a, account: '111122223333', region: eu-west-1}]\n",
		"cluster account":      "version: 1\nclusters: [{name: a, account: x}]\n",
		"cluster issuer":       "version: 1\nclusters: [{name: a, oidc_issuer: 'http://x'}]\n",
		"intended incomplete":  "version: 1\nintended_access: [{principal: a}]\n",
		"cut cost zero":        "version: 1\nremediation: {cut_costs: {ASSUMES: 0}}\n",
		"uncuttable no reason": "version: 1\nremediation: {uncuttable_edges: [{kind: a, from: b, to: c}]}\n",
		"negative tolerance":   "version: 1\ncoverage: {tolerance: {unresolved: -1}}\n",
		"unclassified value":   "version: 1\ncrown_jewels: {unclassified: skip}\n",
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestIgnoreFile(t *testing.T) {
	s, err := ParseIgnore([]byte(`suppressions:
  - {fingerprint: bb, reason: accepted, owner: team-a, expires: "2026-12-31"}
  - {fingerprint: aa, reason: accepted, owner: team-a, expires: "2026-01-01"}
`))
	if err != nil || s[0].Fingerprint != "aa" {
		t.Fatalf("got %+v %v", s, err)
	}
	day := time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC)
	if !s[1].Active(day) || s[0].Active(day) {
		t.Error("expiry day is inclusive; past expiry re-fires")
	}
	bad := (&Suppression{Expires: "soon"})
	if bad.Active(day) {
		t.Error("unparsable expiry is not active")
	}
	for name, y := range map[string]string{
		"missing owner": `suppressions: [{fingerprint: a, reason: r, expires: "2026-01-01"}]`,
		"bad date":      `suppressions: [{fingerprint: a, reason: r, owner: o, expires: "31/12/2026"}]`,
		"duplicate":     `suppressions: [{fingerprint: a, reason: r, owner: o, expires: "2026-01-01"}, {fingerprint: a, reason: r, owner: o, expires: "2026-01-01"}]`,
		"unknown field": `suppressions: [{fingerprint: a, why: r}]`,
	} {
		if _, err := ParseIgnore([]byte(y)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "config") {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
