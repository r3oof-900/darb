package awssnapshot

import (
	"encoding/base64"
	"path"
	"slices"

	"github.com/r3oof-900/darb/internal/collect/awsraw"
)

// credentials writes the credential files (iam.go reads them): the report
// as aws iam get-credential-report prints it, each user's access keys, and
// each key's last use when the report could not be read.
func (w *writer) credentials(a *awsraw.Account) {
	if r := a.CredentialReport; r != nil {
		w.file(path.Join(a.ID, "iam", "get-credential-report.json"), map[string]any{
			"Content": base64.StdEncoding.EncodeToString(r.Content), "ReportFormat": "text/csv", "GeneratedTime": r.GeneratedTime,
		})
	}
	users := make([]string, 0, len(a.AccessKeys))
	for u := range a.AccessKeys {
		users = append(users, u)
	}
	slices.Sort(users)
	for _, u := range users {
		w.file(path.Join(a.ID, "iam", "users", escapeName(u), "list-access-keys.json"),
			map[string]any{"AccessKeyMetadata": append([]awsraw.AccessKeyMetadata{}, a.AccessKeys[u]...)})
	}
	keys := make([]string, 0, len(a.KeyLastUsed))
	for k := range a.KeyLastUsed {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		w.file(path.Join(a.ID, "iam", "access-keys", escapeName(k), "get-access-key-last-used.json"),
			map[string]any{"AccessKeyLastUsed": map[string]string{"LastUsedDate": a.KeyLastUsed[k]}})
	}
}
