// Command refresh-managed-policies regenerates the vendored AWS managed
// policy snapshot (internal/managedpolicies/data/managed-policies.json) from
// IAM. It makes two read-only calls and needs exactly these permissions:
//
//   - iam:ListPolicies on "*", with Scope=AWS (the AWS-owned policies only),
//     which also returns each policy's DefaultVersionId;
//   - iam:GetPolicyVersion on arn:aws:iam::aws:policy/* for that version.
//
// (iam:GetPolicy is not needed: ListPolicies already names the default
// version.) Credentials come from the SDK's own chain for the profile; the
// command never reads, asks for or prints them.
//
// Usage:
//
//	go run ./tools/refresh-managed-policies --profile clapa-refresh
//
// The output is deterministic: the same policies give the same bytes (sorted
// by ARN, documents compact, one policy per line). Review the diff before
// committing.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

const (
	snapshotPath = "internal/managedpolicies/data/managed-policies.json"
	format       = "clapa-managed-policies/v2"
	source       = "IAM ListPolicies (Scope=AWS) and GetPolicyVersion of each policy's DefaultVersionId, refreshed with tools/refresh-managed-policies."
)

// policy is one AWS managed policy at its default version.
type policy struct {
	ARN              string
	DefaultVersionID string
	Document         []byte // compact JSON
}

// api is the part of the IAM client the command uses.
type api interface {
	ListPolicies(ctx context.Context, in *iam.ListPoliciesInput, opts ...func(*iam.Options)) (*iam.ListPoliciesOutput, error)
	GetPolicyVersion(ctx context.Context, in *iam.GetPolicyVersionInput, opts ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "refresh-managed-policies:", err)
		os.Exit(1)
	}
}

func run() error {
	profile := flag.String("profile", "", "AWS profile (shared configuration); the SDK reads its credentials")
	partition := flag.String("partition", "aws", "AWS partition of the policies")
	timeout := flag.Duration("timeout", 30*time.Minute, "overall timeout")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var opts []func(*config.LoadOptions) error
	if *profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(*profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("loading AWS configuration: %w", err)
	}
	policies, err := collect(ctx, iam.NewFromConfig(cfg), *partition)
	if err != nil {
		return err
	}
	data, err := render(policies, time.Now().UTC().Format(time.DateOnly), *partition)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.FromSlash(snapshotPath), data, 0o600); err != nil {
		return fmt.Errorf("writing %s (run from the repository root): %w", snapshotPath, err)
	}
	fmt.Fprintf(os.Stderr, "%d policies, %d bytes written to %s\n", len(policies), len(data), snapshotPath)
	return nil
}

// collect lists the AWS-owned policies and fetches each default version.
func collect(ctx context.Context, client api, partition string) ([]policy, error) {
	var listed []types.Policy
	pages := iam.NewListPoliciesPaginator(client, &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeAws})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListPolicies: %w", err)
		}
		listed = append(listed, page.Policies...)
	}
	prefix := "arn:" + partition + ":iam::aws:policy/"
	out := make([]policy, 0, len(listed))
	for i := range listed {
		p := &listed[i]
		arn, version := aws.ToString(p.Arn), aws.ToString(p.DefaultVersionId)
		if !strings.HasPrefix(arn, prefix) || version == "" {
			return nil, fmt.Errorf("ListPolicies returned %q (default version %q), not an AWS managed policy of %s", arn, version, partition)
		}
		gv, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: aws.String(arn), VersionId: aws.String(version)})
		if err != nil {
			return nil, fmt.Errorf("GetPolicyVersion %s %s: %w", arn, version, err)
		}
		doc, err := decode(aws.ToString(gv.PolicyVersion.Document))
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", arn, version, err)
		}
		out = append(out, policy{ARN: arn, DefaultVersionID: version, Document: doc})
	}
	return out, nil
}

// decode turns IAM's document (URL-encoded per RFC 3986) into compact
// JSON. PathUnescape, not QueryUnescape: a "+" is not a space.
func decode(encoded string) ([]byte, error) {
	text, err := url.PathUnescape(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding the document: %w", err)
	}
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(text)); err != nil {
		return nil, fmt.Errorf("the document is not valid JSON: %w", err)
	}
	return b.Bytes(), nil
}

// render writes the snapshot: metadata, then the policies sorted by ARN,
// one per line. The same policies and date give the same bytes.
func render(policies []policy, date, partition string) ([]byte, error) {
	ps := slices.Clone(policies)
	slices.SortFunc(ps, func(a, b policy) int { return strings.Compare(a.ARN, b.ARN) })
	for i := 1; i < len(ps); i++ {
		if ps[i].ARN == ps[i-1].ARN {
			return nil, errors.New("duplicate policy " + ps[i].ARN)
		}
	}
	nl := string(rune(10))
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	var b strings.Builder
	b.WriteString("{" + nl)
	b.WriteString(`  "format": ` + q(format) + "," + nl)
	b.WriteString(`  "snapshot_date": ` + q(date) + "," + nl)
	b.WriteString(`  "partition": ` + q(partition) + "," + nl)
	b.WriteString(`  "policy_count": ` + strconv.Itoa(len(ps)) + "," + nl)
	b.WriteString(`  "source": ` + q(source) + "," + nl)
	b.WriteString(`  "policies": [` + nl)
	for i, p := range ps {
		b.WriteString(`    {"arn": ` + q(p.ARN) + `, "default_version_id": ` + q(p.DefaultVersionID) + `, "document": ` + string(p.Document) + "}")
		if i < len(ps)-1 {
			b.WriteString(",")
		}
		b.WriteString(nl)
	}
	b.WriteString("  ]" + nl + "}" + nl)
	out := []byte(b.String())
	if !json.Valid(out) {
		return nil, errors.New("the rendered snapshot is not valid JSON")
	}
	return out, nil
}
