package eval

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/r3oof-900/darb/internal/arn"
	"github.com/r3oof-900/darb/internal/eval/condition"
)

// Credential is what a request is signed with.
type Credential string

// Credential kinds (DESIGN.md §6.2, documented keys).
const (
	// RoleSession: temporary credentials of a role (IRSA, Pod Identity,
	// sts:AssumeRole).
	RoleSession Credential = "role-session"
	// LongTerm: an IAM user's access key.
	LongTerm Credential = "long-term"
	// NoCredential: an anonymous request.
	NoCredential Credential = "anonymous"
	// ConsoleSession: an IAM user signed in to the console (item 4: a
	// password someone else set with CreateLoginProfile).
	ConsoleSession Credential = "console"
)

// RequestFacts are what the documented keys of one request depend on.
type RequestFacts struct {
	Credential Credential
	Action     string
	Resource   string
	// Via: the service principal of a forward access session (S3 calling
	// KMS for SSE-KMS: "s3.amazonaws.com"); "" for a direct request.
	Via string
	// Now: the scan time; zero leaves the time keys unknown.
	Now time.Time
}

// Documented sources, cited by every row (DESIGN.md §6.2).
const (
	srcKeys   = "IAM User Guide › AWS global condition context keys"
	srcFAS    = "IAM User Guide › Forward access sessions; IAM User Guide › AWS global condition context keys › aws:CalledVia"
	srcMFA    = "IAM User Guide › AWS global condition context keys › aws:MultiFactorAuthPresent; Configuring MFA-protected API access"
	srcS3Keys = "Amazon S3 User Guide › Policy condition keys for Amazon S3"
	srcSM     = "Secrets Manager User Guide › Condition keys for AWS Secrets Manager"
	srcSTS    = "IAM User Guide › Available keys for AWS STS › sts:RoleSessionName"
	// attackerValue: a value no policy names, for free-text keys.
	attackerValue = "darb-attacker-chosen-value"
)

// keyRow is one row of the documented-keys table: the keys it decides, for
// which requests, and how. A new key of the same kind is a new row.
type keyRow struct {
	keys    []string
	actions []string     // action patterns it applies to; nil: every action
	creds   []Credential // credential kinds; nil: every kind
	direct  bool         // only for a direct request
	fas     bool         // only for a forward access session
	// present: the value is known (nil with no choice: absent).
	present func(f *RequestFacts) []string
	choice  *condition.Choice
}

// keyTable: every key whose value darb takes from the documentation.
func keyTable() []keyRow {
	bools := func(vs ...string) []condition.Option {
		out := make([]condition.Option, 0, len(vs))
		for _, v := range vs {
			out = append(out, condition.Option{"": {v}})
		}
		return out
	}
	attacker := func(key string, free bool, opts []condition.Option, src string) *condition.Choice {
		return &condition.Choice{Keys: []string{key}, Options: opts, By: condition.ByAttacker, Free: free, Fresh: attackerValue, Source: src}
	}
	absentOr := []condition.Option{{}} // optional: the caller may leave it out
	return []keyRow{
		{keys: []string{"aws:SecureTransport"}, direct: true, choice: attacker("aws:SecureTransport", false, bools("true", "false"), srcKeys+" › aws:SecureTransport")},
		{keys: []string{"aws:UserAgent"}, direct: true, choice: attacker("aws:UserAgent", true, absentOr, srcKeys+" › aws:UserAgent")},
		{keys: []string{"aws:Referer"}, direct: true, choice: attacker("aws:Referer", true, absentOr, srcKeys+" › aws:Referer")},
		{keys: []string{"aws:RequestedRegion"}, direct: true, present: requestedRegion},
		{keys: []string{"aws:RequestedRegion"}, direct: true, choice: attacker("aws:RequestedRegion", true, nil, srcKeys+" › aws:RequestedRegion")},
		{keys: []string{"s3:TlsVersion"}, actions: []string{"s3:*"}, direct: true, choice: attacker("s3:TlsVersion", false, bools("1.2", "1.3"), srcS3Keys)},
		{keys: []string{"s3:signatureversion"}, actions: []string{"s3:*"}, direct: true, choice: attacker("s3:signatureversion", false, bools("AWS4-HMAC-SHA256"), srcS3Keys)},
		{keys: []string{"s3:authType"}, actions: []string{"s3:*"}, direct: true, choice: attacker("s3:authType", false, bools("REST-HEADER", "REST-QUERY-STRING", "POST"), srcS3Keys)},
		{keys: []string{"s3:prefix"}, actions: []string{"s3:ListBucket*"}, direct: true, choice: attacker("s3:prefix", true, absentOr, srcS3Keys)},
		{keys: []string{"s3:delimiter"}, actions: []string{"s3:ListBucket*"}, direct: true, choice: attacker("s3:delimiter", true, absentOr, srcS3Keys)},
		{keys: []string{"s3:max-keys"}, actions: []string{"s3:ListBucket*"}, direct: true, choice: &condition.Choice{
			Keys: []string{"s3:max-keys"}, Options: absentOr, By: condition.ByAttacker, Free: true, Fresh: "1", Source: srcS3Keys,
		}},
		{
			keys: []string{"secretsmanager:VersionStage"}, actions: []string{"secretsmanager:GetSecretValue"}, direct: true,
			choice: attacker("secretsmanager:VersionStage", true, absentOr, srcSM),
		},
		{
			keys: []string{"secretsmanager:VersionId"}, actions: []string{"secretsmanager:GetSecretValue"}, direct: true,
			choice: attacker("secretsmanager:VersionId", true, absentOr, srcSM),
		},
		{keys: []string{"sts:RoleSessionName"}, actions: []string{"sts:AssumeRole"}, direct: true, choice: attacker("sts:RoleSessionName", true, nil, srcSTS)},
		// Set by AWS: false for a direct request, true for a forward access
		// session ("always included in the request context").
		{keys: []string{"aws:ViaAWSService"}, direct: true, present: func(*RequestFacts) []string { return []string{"false"} }},
		{keys: []string{"aws:ViaAWSService"}, fas: true, present: func(*RequestFacts) []string { return []string{"true"} }},
		// Not present when the principal calls directly.
		{keys: []string{"aws:CalledVia", "aws:CalledViaFirst", "aws:CalledViaLast"}, direct: true},
		// A forward access session: the FAS page says the keys hold the
		// calling service; the list published with the key named athena,
		// cloudformation, dynamodb and kms only. Undocumented for S3,
		// Secrets Manager and SSM: absent, or all three set together.
		{keys: []string{"aws:CalledVia", "aws:CalledViaFirst", "aws:CalledViaLast"}, fas: true, choice: &condition.Choice{
			Keys: []string{"aws:CalledVia", "aws:CalledViaFirst", "aws:CalledViaLast"}, By: condition.Undocumented, Source: srcFAS,
		}},
		// A console sign-in without MFA: the key is "present in the
		// request and set to a value of false".
		{keys: []string{"aws:MultiFactorAuthPresent"}, creds: []Credential{ConsoleSession}, present: func(*RequestFacts) []string { return []string{"false"} }},
		// Long-term credentials "do not include this key"; an anonymous
		// request carries no credentials. A role session: the documentation
		// does not say whether it is absent or false.
		{keys: []string{"aws:MultiFactorAuthPresent"}, creds: []Credential{LongTerm, NoCredential}},
		{keys: []string{"aws:MultiFactorAuthPresent"}, creds: []Credential{RoleSession}, choice: &condition.Choice{
			Keys: []string{"aws:MultiFactorAuthPresent"}, Options: []condition.Option{{}, {"aws:MultiFactorAuthPresent": {"false"}}},
			By: condition.Undocumented, Source: srcMFA,
		}},
		// The scan time ("always included"); a report note says so.
		{keys: []string{"aws:CurrentTime"}, present: func(f *RequestFacts) []string { return timeValue(f, time.RFC3339) }},
		{keys: []string{"aws:EpochTime"}, present: func(f *RequestFacts) []string { return timeValue(f, "") }},
	}
}

// DocumentedKeys returns the keys of a request whose value the documentation
// decides (present, absent) or bounds (choices), DESIGN.md §6.2. Keys a
// caller states itself win (the caller applies them after).
func DocumentedKeys(f *RequestFacts) (present map[string][]string, absent []string, choices []condition.Choice) {
	present = map[string][]string{}
	decided := map[string]bool{}
	for _, row := range keyTable() {
		if !row.applies(f) || slices.ContainsFunc(row.keys, func(k string) bool { return decided[k] }) {
			continue
		}
		switch {
		case row.present != nil:
			v := row.present(f)
			if v == nil {
				continue // not known here: a later row decides
			}
			present[row.keys[0]] = v
		case row.choice != nil:
			ch := row.choice.Clone()
			ch.Options = fill(&ch, f)
			choices = append(choices, ch)
		default:
			absent = append(absent, row.keys...)
		}
		for _, k := range row.keys {
			decided[k] = true
		}
	}
	return present, absent, choices
}

func (row *keyRow) applies(f *RequestFacts) bool {
	if row.direct && f.Via != "" || row.fas && f.Via == "" {
		return false
	}
	if row.creds != nil && !slices.Contains(row.creds, f.Credential) {
		return false
	}
	return row.actions == nil || slices.ContainsFunc(row.actions, func(p string) bool { return actionMatches(p, f.Action) })
}

func actionMatches(pattern, action string) bool {
	p, a := strings.ToLower(pattern), strings.ToLower(action)
	if prefix, ok := strings.CutSuffix(p, "*"); ok {
		return strings.HasPrefix(a, prefix)
	}
	return p == a
}

// fill: options written with the "" key name the row's key; the joint
// CalledVia option sets all three keys to the calling service.
func fill(ch *condition.Choice, f *RequestFacts) []condition.Option {
	if ch.Keys[0] == "aws:CalledVia" {
		via := []string{f.Via}
		return []condition.Option{{}, {"aws:CalledVia": via, "aws:CalledViaFirst": via, "aws:CalledViaLast": via}}
	}
	out := make([]condition.Option, 0, len(ch.Options))
	for _, o := range ch.Options {
		if vs, ok := o[""]; ok {
			o = condition.Option{ch.Keys[0]: vs}
		}
		out = append(out, o)
	}
	return out
}

// requestedRegion: the region a request goes to, when the request decides
// it: the resource's region, or us-east-1 for IAM, a global service; nil
// otherwise (the caller chooses: the next row).
func requestedRegion(f *RequestFacts) []string {
	if strings.HasPrefix(strings.ToLower(f.Action), "iam:") {
		return []string{"us-east-1"}
	}
	if a, err := arn.Parse(f.Resource); err == nil && a.Region != "" {
		return []string{a.Region}
	}
	return nil
}

func timeValue(f *RequestFacts, layout string) []string {
	if f.Now.IsZero() {
		return nil
	}
	if layout == "" {
		return []string{strconv.FormatInt(f.Now.Unix(), 10)}
	}
	return []string{f.Now.UTC().Format(layout)}
}
