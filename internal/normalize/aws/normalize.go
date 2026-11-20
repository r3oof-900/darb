package aws

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/r3oof-900/clapa/internal/collect/awsraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/iampolicy"
	"github.com/r3oof-900/clapa/internal/managedpolicies"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/normalize"
)

// Name identifies this normalizer in coverage gaps.
const Name = "normalize-aws"

// Normalize converts snapshot (or live) AWS data into canonical nodes.
func Normalize(s *awsraw.Snapshot, mp *managedpolicies.Snapshot, b *normalize.Builder, rec *coverage.Recorder) {
	for _, a := range s.Accounts {
		n := &norm{acct: a, mp: mp, b: b, rec: rec, managed: map[string]*awsraw.ManagedPolicy{}}
		n.iam()
		n.keys()
		n.buckets()
		n.clusters()
	}
}

type norm struct {
	acct    *awsraw.Account
	mp      *managedpolicies.Snapshot
	b       *normalize.Builder
	rec     *coverage.Recorder
	managed map[string]*awsraw.ManagedPolicy // customer managed, by ARN
}

func (n *norm) gap(kind coverage.Kind, address, detail string) {
	n.rec.Add(&coverage.Gap{Kind: kind, Source: Name, Account: n.acct.ID, Address: address, Detail: detail})
}

func apiLoc(arn, api string) model.SourceLocation { return model.APILocation(arn, api) }

// policyText decodes a policy document: the IAM API returns URL-encoded
// strings, the CLI decoded objects; KMS and S3 return JSON strings.
func policyText(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", fmt.Errorf("missing policy document")
	}
	if raw[0] != '"' {
		return string(raw), nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("policy document string: %w", err)
	}
	if strings.HasPrefix(strings.TrimSpace(s), "{") {
		return s, nil
	}
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return "", fmt.Errorf("URL-decoding policy document: %w", err)
	}
	return decoded, nil
}

// parse builds a policy; a document that cannot be read is an unknown
// document and a coverage gap, never an empty (deny-all) one.
func (n *norm) parse(raw json.RawMessage, id string, kind model.PolicyKind, loc *model.SourceLocation) *model.PolicyDocument {
	text, err := policyText(raw)
	if err == nil {
		d, perr := iampolicy.Parse([]byte(text), &iampolicy.Options{ID: id, Kind: kind, Source: *loc})
		if perr == nil {
			return d
		}
		err = perr
	}
	n.gap(coverage.KindParseError, id, err.Error())
	return n.unknownDoc(id, kind, loc)
}

func (n *norm) unknownDoc(id string, kind model.PolicyKind, loc *model.SourceLocation) *model.PolicyDocument {
	p := n.b.Placeholder(strings.NewReplacer(":", "_", "/", "_").Replace(id))
	allow := map[string]any{"Effect": "Allow", "Action": p, "Resource": p}
	deny := map[string]any{"Effect": "Deny", "Action": p, "Resource": "*"}
	if kind == model.PolicyResource {
		allow["Principal"] = map[string]any{"AWS": p}
		deny["Principal"] = map[string]any{"AWS": p}
	}
	js, _ := json.Marshal(map[string]any{"Version": model.Version2012, "Statement": []any{allow, deny}})
	d, _ := iampolicy.Parse(js, &iampolicy.Options{ID: id, Kind: kind, Source: *loc, Placeholders: true}) // always valid
	return d
}

func tagMap(ts []awsraw.Tag) map[string]string {
	out := make(map[string]string, len(ts))
	for _, t := range ts {
		out[t.Key] = t.Value
	}
	return out
}
