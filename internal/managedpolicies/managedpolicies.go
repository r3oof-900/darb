package managedpolicies

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

//go:embed data/managed-policies.json
var snapshotJSON []byte

// Policy is one AWS managed policy at its default version.
type Policy struct {
	ARN      string          `json:"arn"`
	Version  string          `json:"version"`
	Document json.RawMessage `json:"document"`
}

// Snapshot is the vendored, versioned set of AWS managed policies.
type Snapshot struct {
	Format       string   `json:"format"`
	SnapshotDate string   `json:"snapshot_date"`
	Source       string   `json:"source"`
	Policies     []Policy `json:"policies"`
}

// Load decodes the embedded snapshot.
func Load() (*Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(snapshotJSON, &s); err != nil {
		return nil, fmt.Errorf("managedpolicies: embedded snapshot: %w", err)
	}
	if s.Format != "clapa-managed-policies/v1" {
		return nil, fmt.Errorf("managedpolicies: unexpected format %q", s.Format)
	}
	slices.SortFunc(s.Policies, func(a, b Policy) int { return strings.Compare(a.ARN, b.ARN) })
	return &s, nil
}

// Lookup returns the policy for an ARN. A managed policy that is not in the
// snapshot is not guessed: callers record it as a coverage gap.
func (s *Snapshot) Lookup(arn string) (*Policy, bool) {
	i, ok := slices.BinarySearchFunc(s.Policies, arn, func(p Policy, target string) int { return strings.Compare(p.ARN, target) })
	if !ok {
		return nil, false
	}
	return &s.Policies[i], true
}

// IsAWSManaged reports whether arn is an AWS managed policy ARN
// (arn:<partition>:iam::aws:policy/...).
func IsAWSManaged(arn string) bool {
	_, rest, ok := strings.Cut(arn, ":iam::aws:policy/")
	return ok && rest != ""
}
