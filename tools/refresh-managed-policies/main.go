// Command refresh-managed-policies regenerates the vendored AWS managed
// policy snapshot (internal/managedpolicies/data/managed-policies.json) from
// IAM, read-only: iam:GetPolicy and iam:GetPolicyVersion for every ARN
// already in the snapshot plus any given with -add.
//
// Usage (credentials from the default AWS chain; only read calls are made):
//
//	go run ./tools/refresh-managed-policies -add arn:aws:iam::aws:policy/ReadOnlyAccess
//
// The output is sorted and deterministic; review the diff before committing.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

const snapshotPath = "internal/managedpolicies/data/managed-policies.json"

type policy struct {
	ARN      string          `json:"arn"`
	Version  string          `json:"version"`
	Document json.RawMessage `json:"document"`
}

type snapshot struct {
	Format       string   `json:"format"`
	SnapshotDate string   `json:"snapshot_date"`
	Source       string   `json:"source"`
	Policies     []policy `json:"policies"`
}

type arnList []string

func (a *arnList) String() string     { return strings.Join(*a, ",") }
func (a *arnList) Set(v string) error { *a = append(*a, v); return nil }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "refresh-managed-policies:", err)
		os.Exit(1)
	}
}

func run() error {
	var add arnList
	flag.Var(&add, "add", "AWS managed policy ARN to add (repeatable)")
	timeout := flag.Duration("timeout", 2*time.Minute, "overall timeout")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	current, err := readSnapshot()
	if err != nil {
		return err
	}
	arns := slices.Clone(add)
	for _, p := range current.Policies {
		arns = append(arns, p.ARN)
	}
	slices.Sort(arns)
	arns = slices.Compact(arns)

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("loading AWS configuration: %w", err)
	}
	client := iam.NewFromConfig(cfg)
	out := snapshot{
		Format: "clapa-managed-policies/v1", SnapshotDate: time.Now().UTC().Format(time.DateOnly),
		Source: "IAM GetPolicy/GetPolicyVersion (default versions), refreshed with tools/refresh-managed-policies.",
	}
	for _, a := range arns {
		p, err := fetch(ctx, client, a)
		if err != nil {
			return err
		}
		out.Policies = append(out.Policies, p)
	}
	return writeSnapshot(&out)
}

func fetch(ctx context.Context, client *iam.Client, policyARN string) (policy, error) {
	gp, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(policyARN)})
	if err != nil {
		return policy{}, fmt.Errorf("GetPolicy %s: %w", policyARN, err)
	}
	version := aws.ToString(gp.Policy.DefaultVersionId)
	gv, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: aws.String(policyARN), VersionId: aws.String(version)})
	if err != nil {
		return policy{}, fmt.Errorf("GetPolicyVersion %s %s: %w", policyARN, version, err)
	}
	doc, err := url.QueryUnescape(aws.ToString(gv.PolicyVersion.Document)) // IAM returns URL-encoded JSON
	if err != nil {
		return policy{}, fmt.Errorf("decoding %s: %w", policyARN, err)
	}
	if !json.Valid([]byte(doc)) {
		return policy{}, fmt.Errorf("%s: document is not valid JSON", policyARN)
	}
	return policy{ARN: policyARN, Version: version, Document: json.RawMessage(doc)}, nil
}

func readSnapshot() (*snapshot, error) {
	data, err := os.ReadFile(filepath.FromSlash(snapshotPath))
	if err != nil {
		return nil, fmt.Errorf("run from the repository root: %w", err)
	}
	var s snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", snapshotPath, err)
	}
	return &s, nil
}

func writeSnapshot(s *snapshot) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding snapshot: %w", err)
	}
	if err := os.WriteFile(filepath.FromSlash(snapshotPath), append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", snapshotPath, err)
	}
	return nil
}
