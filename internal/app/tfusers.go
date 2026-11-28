package app

import (
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/access"
	"github.com/r3oof-900/darb/internal/collect/tfraw"
)

// NoteTerraformUsers is the subject of the note that names the IAM users
// and groups a Terraform input defines (item 4: users are entries from AWS
// snapshots and live scans only).
const NoteTerraformUsers = "IAM users in Terraform"

// terraformUsers: a Terraform input's IAM users, groups and access keys are
// not analysed (a configuration does not say which keys are active or when
// they were used): one not-modelled note names them, once per scan.
func (l *loader) terraformUsers(m *tfraw.Module) {
	var names []string
	for _, r := range m.Resources {
		switch r.Type {
		case "aws_iam_user", "aws_iam_group", "aws_iam_access_key", "aws_iam_user_policy", "aws_iam_group_policy":
			names = append(names, r.Address)
		}
	}
	if len(names) == 0 {
		return
	}
	for i, n := range l.notes {
		if n.Subject == NoteTerraformUsers {
			names = append(strings.Split(strings.TrimPrefix(n.Detail, terraformUsersDetail), ", "), names...)
			l.notes = slices.Delete(l.notes, i, i+1)
			break
		}
	}
	slices.Sort(names)
	l.notes = append(l.notes, access.Note{Kind: "not-modelled", Subject: NoteTerraformUsers, Detail: terraformUsersDetail + strings.Join(slices.Compact(names), ", ")})
}

const terraformUsersDetail = "IAM users and groups are analysed as entry points from AWS snapshots and live scans only " +
	"(a configuration does not say which access keys are active); not analysed here: "
