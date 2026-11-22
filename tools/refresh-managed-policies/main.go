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
//	go run ./tools/refresh-managed-policies --profile darb-refresh
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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

const (
	snapshotPath = "internal/managedpolicies/data/managed-policies.json"
	format       = "darb-managed-policies/v2"
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
	h := header{Format: format, Date: time.Now().UTC().Format(time.DateOnly), Partition: *partition, Source: source}
	n, err := writeSnapshot(filepath.FromSlash(snapshotPath), h, policies)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d policies, %d bytes written to %s\n", len(policies), n, snapshotPath)
	return nil
}

// writeSnapshot renders the snapshot and writes it to path; when the
// rendering fails, nothing is written.
func writeSnapshot(path string, h header, policies []policy) (int, error) {
	data, err := renderWith(h, policies)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return 0, fmt.Errorf("writing %s (run from the repository root): %w", path, err)
	}
	return len(data), nil
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

// header is the snapshot's metadata.
type header struct {
	Format, Date, Partition, Source string
}

// snapshotFile and entry are the file's JSON, in its field order.
type snapshotFile struct {
	Format       string  `json:"format"`
	SnapshotDate string  `json:"snapshot_date"`
	Partition    string  `json:"partition"`
	PolicyCount  int     `json:"policy_count"`
	Source       string  `json:"source"`
	Policies     []entry `json:"policies"`
}

type entry struct {
	ARN              string          `json:"arn"`
	DefaultVersionID string          `json:"default_version_id"`
	Document         json.RawMessage `json:"document"`
}

// render writes the snapshot of IAM's policies on a date.
func render(policies []policy, date, partition string) ([]byte, error) {
	return renderWith(header{Format: format, Date: date, Partition: partition, Source: source}, policies)
}

// renderWith writes the snapshot: metadata, then the policies sorted by
// ARN, one per line. The same header and policies give the same bytes.
// Each document must be one JSON object on its own; the file is built by
// encoding/json from structs, never by pasting a document as text, and the
// layout only adds whitespace outside strings to what json.Marshal wrote.
func renderWith(h header, policies []policy) ([]byte, error) {
	ps := slices.Clone(policies)
	slices.SortFunc(ps, func(a, b policy) int { return strings.Compare(a.ARN, b.ARN) })
	f := snapshotFile{Format: h.Format, SnapshotDate: h.Date, Partition: h.Partition, PolicyCount: len(ps), Source: h.Source, Policies: []entry{}}
	for i, p := range ps {
		if i > 0 && p.ARN == ps[i-1].ARN {
			return nil, errors.New("duplicate policy " + p.ARN)
		}
		doc, err := object(p.Document)
		if err != nil {
			return nil, fmt.Errorf("policy %s: the document %w", p.ARN, err)
		}
		f.Policies = append(f.Policies, entry{ARN: p.ARN, DefaultVersionID: p.DefaultVersionID, Document: doc})
	}
	var compact bytes.Buffer
	enc := json.NewEncoder(&compact)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	marshalled := bytes.TrimSuffix(compact.Bytes(), []byte("\n"))
	out := layout(marshalled)
	var check bytes.Buffer
	if err := json.Compact(&check, out); err != nil || !bytes.Equal(check.Bytes(), marshalled) {
		return nil, errors.New("internal error: the layout changed the snapshot's JSON")
	}
	return out, nil
}

// object decodes a document into one JSON value, which must be an object:
// anything after it (`{}}, {"arn": ...`) or any other kind is refused.
func object(doc []byte) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := json.Unmarshal(doc, &raw); err != nil {
		return nil, fmt.Errorf("is not one JSON value: %w", err)
	}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("is not a JSON object")
	}
	return raw, nil
}

// layout writes the file's form: the top-level members one per line
// (indented 2), the policies one per line (indented 4), a space after the
// colons and commas of each policy entry, documents compact. It reads the
// output of json.Marshal and adds whitespace only between tokens; strings
// are copied whole.
func layout(compact []byte) []byte {
	afterOpen := map[int]string{1: "\n  ", 2: "\n    "}
	beforeClose := map[int]string{1: "\n", 2: "\n  "}
	afterComma := map[int]string{1: "\n  ", 2: "\n    ", 3: " "}
	afterColon := map[int]string{1: " ", 3: " "}
	var b bytes.Buffer
	depth := 0
	for i := 0; i < len(compact); i++ {
		c := compact[i]
		switch c {
		case '"':
			end := stringEnd(compact, i)
			b.Write(compact[i : end+1])
			i = end
			continue
		case '}', ']':
			b.WriteString(beforeClose[depth])
			depth--
		}
		b.WriteByte(c)
		switch c {
		case '{', '[':
			depth++
			if next := i + 1; next < len(compact) && compact[next] != '}' && compact[next] != ']' {
				b.WriteString(afterOpen[depth])
			}
		case ',':
			b.WriteString(afterComma[depth])
		case ':':
			b.WriteString(afterColon[depth])
		}
	}
	b.WriteString("\n")
	return b.Bytes()
}

// stringEnd is the index of the quote that closes the string opened at i.
func stringEnd(compact []byte, i int) int {
	for j := i + 1; j < len(compact); j++ {
		switch compact[j] {
		case '\\':
			j++
		case '"':
			return j
		}
	}
	return len(compact) - 1
}
