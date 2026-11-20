package arn

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalid is returned for strings that are not ARNs.
var ErrInvalid = errors.New("arn: invalid ARN")

// ARN is a parsed Amazon Resource Name:
// arn:partition:service:region:account-id:resource.
// The resource part may itself contain ':' and '/'.
type ARN struct {
	Partition string
	Service   string
	Region    string
	Account   string
	Resource  string
}

// Parse splits s into its six colon-separated components. The partition and
// service must be non-empty; region, account and resource may be empty
// (e.g. "arn:aws:s3:::bucket").
func Parse(s string) (*ARN, error) {
	parts := strings.SplitN(s, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("%w: %q", ErrInvalid, s)
	}
	return &ARN{
		Partition: parts[1],
		Service:   parts[2],
		Region:    parts[3],
		Account:   parts[4],
		Resource:  parts[5],
	}, nil
}

// String reassembles the ARN.
func (a *ARN) String() string {
	return "arn:" + a.Partition + ":" + a.Service + ":" + a.Region + ":" + a.Account + ":" + a.Resource
}

// IsAccountRoot reports whether a is an account principal,
// "arn:<partition>:iam::<account>:root".
func (a *ARN) IsAccountRoot() bool {
	return a.Service == "iam" && a.Region == "" && IsAccountID(a.Account) && a.Resource == "root"
}

// IsAccountID reports whether s is a 12-digit AWS account ID.
func IsAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// AccountRoot returns the account principal ARN for an account ID.
func AccountRoot(partition, account string) string {
	return "arn:" + partition + ":iam::" + account + ":root"
}
