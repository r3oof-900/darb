package awsraw

import (
	"bytes"
	"encoding/csv"
	"fmt"
)

// CredentialReport is iam:GetCredentialReport (after GenerateCredentialReport):
// one row per user, plus "<root_account>" for the root (IAM User Guide ›
// Getting credential reports for your AWS account).
type CredentialReport struct {
	// GeneratedTime: when IAM generated it (it may be hours old).
	GeneratedTime string
	Rows          []CredentialRow
	// Content: the report as IAM returned it (CSV), for a snapshot.
	Content []byte
}

// CredentialRow is one user's row; values are as the report writes them
// ("true", "false", "N/A", "not_supported", or a timestamp).
type CredentialRow map[string]string

// RootUser is the user column of the root's row.
const RootUser = "<root_account>"

// ParseCredentialReport reads the report's CSV content.
func ParseCredentialReport(content []byte, generated string) (*CredentialReport, error) {
	rd := csv.NewReader(bytes.NewReader(content))
	rd.FieldsPerRecord = -1
	records, err := rd.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("credential report: %w", err)
	}
	if len(records) == 0 || len(records[0]) < 2 || records[0][0] != "user" || records[0][1] != "arn" {
		return nil, fmt.Errorf("credential report: no user,arn header")
	}
	rep := &CredentialReport{GeneratedTime: generated, Content: bytes.Clone(content)}
	header := records[0]
	for _, rec := range records[1:] {
		if len(rec) != len(header) {
			return nil, fmt.Errorf("credential report: row %q has %d fields, the header %d", rec[0], len(rec), len(header))
		}
		row := CredentialRow{}
		for i, h := range header {
			row[h] = rec[i]
		}
		rep.Rows = append(rep.Rows, row)
	}
	return rep, nil
}

// AccessKeyMetadata is one key of iam:ListAccessKeys.
type AccessKeyMetadata struct {
	UserName    string `json:"UserName"`
	AccessKeyID string `json:"AccessKeyId"`
	Status      string `json:"Status"`
	CreateDate  string `json:"CreateDate"`
}
