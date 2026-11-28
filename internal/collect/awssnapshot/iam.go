package awssnapshot

import (
	"encoding/base64"
	"fmt"

	"github.com/r3oof-900/darb/internal/collect/awsraw"
)

// Credential files (item 4, after v0.1.0-rc.1):
//
//	<account>/iam/get-credential-report.json                   (aws iam get-credential-report)
//	<account>/iam/users/<user>/list-access-keys.json           (aws iam list-access-keys --user-name)
//	<account>/iam/access-keys/<key-id>/get-access-key-last-used.json
//	                                                           (the fallback when the report failed)

// iamFile places one file under <account>/iam/ other than the
// authorization details; false when it is not one of them.
func (r *reader) iamFile(a *awsraw.Account, f string, parts []string) (bool, error) {
	switch {
	case len(parts) == 3 && parts[2] == "get-credential-report.json":
		return true, r.credentialReport(a, f)
	case len(parts) == 5 && parts[2] == "users" && parts[4] == "list-access-keys.json":
		name, err := unescapeName(parts[3])
		if err != nil {
			return true, err
		}
		var v struct {
			Keys []awsraw.AccessKeyMetadata `json:"AccessKeyMetadata"`
		}
		if err := r.json(f, &v); err != nil {
			return true, err
		}
		if a.AccessKeys == nil {
			a.AccessKeys = map[string][]awsraw.AccessKeyMetadata{}
		}
		a.AccessKeys[name] = append([]awsraw.AccessKeyMetadata{}, v.Keys...)
		return true, nil
	case len(parts) == 5 && parts[2] == "access-keys" && parts[4] == "get-access-key-last-used.json":
		var v struct {
			Last struct {
				LastUsedDate string `json:"LastUsedDate"`
			} `json:"AccessKeyLastUsed"`
		}
		if err := r.json(f, &v); err != nil {
			return true, err
		}
		if a.KeyLastUsed == nil {
			a.KeyLastUsed = map[string]string{}
		}
		id, err := unescapeName(parts[3])
		if err != nil {
			return true, err
		}
		a.KeyLastUsed[id] = v.Last.LastUsedDate
		return true, nil
	}
	return false, nil
}

func (r *reader) credentialReport(a *awsraw.Account, f string) error {
	var v struct {
		Content       string `json:"Content"`
		ReportFormat  string `json:"ReportFormat"`
		GeneratedTime string `json:"GeneratedTime"`
	}
	if err := r.json(f, &v); err != nil {
		return err
	}
	if v.ReportFormat != "" && v.ReportFormat != "text/csv" {
		return fmt.Errorf("credential report format %q, want text/csv", v.ReportFormat)
	}
	content, err := base64.StdEncoding.DecodeString(v.Content)
	if err != nil {
		return fmt.Errorf("credential report content: %w", err)
	}
	rep, err := awsraw.ParseCredentialReport(content, v.GeneratedTime)
	if err != nil {
		return err
	}
	a.CredentialReport = rep
	return nil
}
