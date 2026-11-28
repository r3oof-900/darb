package aws

import (
	"slices"
	"strings"
	"time"

	"github.com/r3oof-900/darb/internal/collect/awsraw"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/model"
)

const (
	apiCredentialReport = "iam:GetCredentialReport" //nolint:gosec // G101: an API name, not a credential.
	apiListAccessKeys   = "iam:ListAccessKeys"
)

// users: IAM users with their inline, attached, group and boundary
// policies and their credentials; groups; the versions of customer managed
// policies; the root when the credential report shows it has an active
// access key (item 4, after v0.1.0-rc.1).
func (n *norm) users() {
	auth := n.acct.Auth
	groups := map[string]*model.IAMGroup{}
	for i := range auth.GroupDetailList {
		g := &auth.GroupDetailList[i]
		loc := apiLoc(g.Arn, apiAuthDetails)
		ig := &model.IAMGroup{ARN: g.Arn, Account: n.acct.ID, Source: loc}
		for _, ip := range g.GroupPolicyList {
			ig.Policies = append(ig.Policies, n.parse(ip.PolicyDocument, g.Arn+"#inline/"+ip.PolicyName, model.PolicyIdentity, &loc))
		}
		for _, ap := range g.AttachedManagedPolicies {
			ig.Policies = append(ig.Policies, n.managedDoc(ap.PolicyArn, model.PolicyIdentity))
		}
		groups[g.GroupName] = ig
	}
	attached := map[string][]model.ID{}
	for i := range auth.UserDetailList {
		u := &auth.UserDetailList[i]
		p := n.user(u, groups)
		for _, ap := range u.AttachedManagedPolicies {
			attached[ap.PolicyArn] = append(attached[ap.PolicyArn], p.ID())
		}
		for _, g := range u.GroupList {
			for _, ap := range groupDetail(auth, g).AttachedManagedPolicies {
				attached[ap.PolicyArn] = append(attached[ap.PolicyArn], p.ID())
			}
		}
	}
	for i := range auth.RoleDetailList {
		r := &auth.RoleDetailList[i]
		for _, ap := range r.AttachedManagedPolicies {
			attached[ap.PolicyArn] = append(attached[ap.PolicyArn], model.NewID(model.KindIAMRole, r.Arn))
		}
	}
	for _, g := range groups {
		n.b.AddGroup(g)
	}
	n.versions(attached)
	n.root()
}

func groupDetail(auth *awsraw.AuthorizationDetails, name string) *awsraw.GroupDetail {
	for i := range auth.GroupDetailList {
		if auth.GroupDetailList[i].GroupName == name {
			return &auth.GroupDetailList[i]
		}
	}
	return &awsraw.GroupDetail{}
}

func (n *norm) user(u *awsraw.UserDetail, groups map[string]*model.IAMGroup) *model.Principal {
	loc := apiLoc(u.Arn, apiAuthDetails)
	p := model.NewPrincipal(model.KindIAMUser, u.Arn, n.acct.ID, &loc)
	n.b.AddPrincipal(p)
	for _, ip := range u.UserPolicyList {
		n.b.AddPolicy(&model.AttachedPolicy{Target: p.ID(), Doc: n.parse(ip.PolicyDocument, u.Arn+"#inline/"+ip.PolicyName, model.PolicyIdentity, &loc)})
	}
	for _, ap := range u.AttachedManagedPolicies {
		n.b.AddPolicy(&model.AttachedPolicy{Target: p.ID(), Doc: n.managedDoc(ap.PolicyArn, model.PolicyIdentity)})
	}
	for _, name := range u.GroupList {
		g, ok := groups[name]
		if !ok {
			n.gap(coverage.KindUnresolved, u.Arn, "group "+name+" is not in the authorization details; its policies are unknown")
			continue
		}
		g.Members = append(g.Members, p.ID())
		for _, d := range g.Policies {
			n.b.AddPolicy(&model.AttachedPolicy{Target: p.ID(), Doc: d})
		}
	}
	if u.PermissionsBoundary != nil && u.PermissionsBoundary.PermissionsBoundaryArn != "" {
		n.b.AddBoundary(&model.AttachedPolicy{Target: p.ID(), Doc: n.managedDoc(u.PermissionsBoundary.PermissionsBoundaryArn, model.PolicyBoundary)})
	}
	n.b.AddCredentials(n.credentials(u.UserName, u.Arn, p.ID()))
	return p
}

// versions records each customer managed policy's stored versions.
func (n *norm) versions(attached map[string][]model.ID) {
	for _, mp := range n.acct.Auth.Policies {
		if strings.Contains(mp.Arn, ":iam::aws:policy/") {
			continue
		}
		loc := apiLoc(mp.Arn, apiAuthDetails)
		v := &model.ManagedPolicyVersions{ARN: mp.Arn, Account: n.acct.ID, Count: len(mp.PolicyVersionList), Attached: attached[mp.Arn]}
		for _, pv := range mp.PolicyVersionList {
			if pv.IsDefaultVersion || pv.VersionID == mp.DefaultVersionID {
				continue
			}
			v.Others = append(v.Others, n.parse(pv.Document, mp.Arn+"#"+pv.VersionID, model.PolicyIdentity, &loc))
		}
		slices.Sort(v.Attached)
		n.b.AddManagedPolicy(v)
	}
}

// credentials: from the credential report (state, dates, password, MFA)
// with ListAccessKeys for the key IDs; ListAccessKeys (and
// GetAccessKeyLastUsed) alone when the report is missing; unknown, with a
// gap naming the missing calls, when neither is in the input.
func (n *norm) credentials(name, userARN string, id model.ID) *model.Credentials {
	c := &model.Credentials{Principal: id, Known: model.Unknown, KeyCount: -1, Password: model.Unknown, MFA: model.Unknown}
	listed, haveList := n.acct.AccessKeys[name]
	if row := n.reportRow(userARN); row != nil {
		c.Known, c.Generated = model.True, n.acct.CredentialReport.GeneratedTime
		c.Source = apiLoc(userARN, apiCredentialReport)
		c.Password, c.MFA = reportTri(row["password_enabled"]), reportTri(row["mfa_active"])
		for _, slot := range []string{"1", "2"} {
			rotated := row["access_key_"+slot+"_last_rotated"]
			if rotated == "" || rotated == "N/A" { // N/A: no key in this slot
				continue
			}
			k := model.AccessKey{Active: row["access_key_"+slot+"_active"] == "true", Created: rotated, LastUsed: reportValue(row["access_key_"+slot+"_last_used_date"])}
			k.ID = matchKeyID(listed, rotated)
			c.Keys = append(c.Keys, k)
		}
		c.KeyCount = len(c.Keys)
		return c
	}
	if haveList {
		c.Known, c.Source = model.True, apiLoc(userARN, apiListAccessKeys)
		for _, k := range listed {
			c.Keys = append(c.Keys, model.AccessKey{ID: k.AccessKeyID, Active: k.Status == "Active", Created: k.CreateDate, LastUsed: n.acct.KeyLastUsed[k.AccessKeyID]})
		}
		c.KeyCount = len(c.Keys)
		return c
	}
	n.gap(coverage.KindUnresolved, userARN, "the access keys of "+userARN+" are not in the input ("+apiCredentialReport+", "+apiListAccessKeys+
		"): the user is an entry at the worst case (credential-leak), unconfirmed")
	return c
}

func (n *norm) reportRow(arn string) awsraw.CredentialRow {
	if n.acct.CredentialReport == nil {
		return nil
	}
	for _, r := range n.acct.CredentialReport.Rows {
		if r["arn"] == arn {
			return r
		}
	}
	return nil
}

// root: the account root is a principal (and an entry) only when the
// credential report shows an active access key for it.
func (n *norm) root() {
	if n.acct.CredentialReport == nil {
		return
	}
	for _, r := range n.acct.CredentialReport.Rows {
		if r["user"] != awsraw.RootUser {
			continue
		}
		active := r["access_key_1_active"] == "true" || r["access_key_2_active"] == "true"
		if !active {
			return
		}
		loc := apiLoc(r["arn"], apiCredentialReport)
		p := model.NewPrincipal(model.KindAccountRoot, r["arn"], n.acct.ID, &loc)
		n.b.AddPrincipal(p)
		n.b.AddCredentials(n.credentials(awsraw.RootUser, r["arn"], p.ID()))
		return
	}
}

func reportTri(v string) model.Tri {
	switch v {
	case "true":
		return model.True
	case "false":
		return model.False
	}
	return model.Unknown
}

func reportValue(v string) string {
	if v == "N/A" || v == "no_information" {
		return ""
	}
	return v
}

// matchKeyID: the listed key created when the report says the slot's key
// was last rotated (the report gives no key ID).
func matchKeyID(listed []awsraw.AccessKeyMetadata, rotated string) string {
	want, err := time.Parse(time.RFC3339, rotated)
	if err != nil {
		return ""
	}
	for _, k := range listed {
		if got, err := time.Parse(time.RFC3339, k.CreateDate); err == nil && got.Equal(want) {
			return k.AccessKeyID
		}
	}
	return ""
}
