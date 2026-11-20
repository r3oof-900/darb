package eval

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/r3oof-900/clapa/internal/eval/condition"
	"github.com/r3oof-900/clapa/internal/eval/match"
	"github.com/r3oof-900/clapa/internal/iampolicy"
	"github.com/r3oof-900/clapa/internal/model"
)

func buildCase(t *testing.T, c *caseSpec) (*Request, *PolicySet) {
	t.Helper()
	if c.Principal == nil {
		t.Fatal("case has no principal")
	}
	req := &Request{
		Principal: match.RequestPrincipal{
			Kind: principalKind(t, c.Principal.Kind), ARN: c.Principal.ARN, Account: c.Principal.Account,
			SourceARN: c.Principal.Source, CanonicalUser: c.Principal.Canonical,
		},
		Action:   c.Action,
		Resource: c.Resource,
	}
	if c.ResourceAccount != nil {
		req.ResourceAccount = *c.ResourceAccount
	}
	if c.Context != nil {
		req.Context = buildContext(t, c.Context)
	}
	p := &c.Policies
	ps := &PolicySet{
		Identity: docs(t, "identity", model.PolicyIdentity, p.Identity),
		Resource: docs(t, "resource", model.PolicyResource, p.Resource),
		Session:  docs(t, "session", model.PolicySession, p.Session),
		SCPs:     levels(t, "scp", model.PolicySCP, p.SCPs),
		RCPs:     levels(t, "rcp", model.PolicyRCP, p.RCPs),
	}
	if p.Boundary != nil {
		ps.Boundary = doc(t, "boundary", model.PolicyBoundary, p.Boundary)
	}
	if p.Required != nil {
		ps.ResourcePolicyRequired = *p.Required
	}
	return req, ps
}

func principalKind(t *testing.T, s string) match.PrincipalKind {
	t.Helper()
	switch s {
	case "iam-user":
		return match.KindIAMUser
	case "assumed-role":
		return match.KindAssumedRole
	case "federated-user":
		return match.KindFederatedUser
	case "root":
		return match.KindAccountRoot
	case "service":
		return match.KindService
	case "web-identity":
		return match.KindWebIdentity
	case "anonymous":
		return match.KindAnonymous
	}
	t.Fatalf("unknown principal kind %q", s)
	return 0
}

func buildContext(t *testing.T, c *contextSpec) *condition.Context {
	t.Helper()
	in := &condition.Input{Absent: c.Absent, Unknown: c.Unknown, Present: map[string][]string{}}
	switch c.Default {
	case "", "unknown":
		in.Default = condition.StateUnknown
	case "absent":
		in.Default = condition.StateAbsent
	default:
		t.Fatalf("context default must be unknown or absent, got %q", c.Default)
	}
	for k, v := range c.Present {
		in.Present[k] = v
	}
	return condition.NewContext(in)
}

func levels(t *testing.T, prefix string, kind model.PolicyKind, ls [][]json.RawMessage) [][]*model.PolicyDocument {
	t.Helper()
	if ls == nil {
		return nil
	}
	out := make([][]*model.PolicyDocument, 0, len(ls))
	for i, l := range ls {
		out = append(out, docs(t, fmt.Sprintf("%s[%d]", prefix, i), kind, l))
	}
	return out
}

func docs(t *testing.T, prefix string, kind model.PolicyKind, raws []json.RawMessage) []*model.PolicyDocument {
	t.Helper()
	if raws == nil {
		return nil
	}
	out := make([]*model.PolicyDocument, 0, len(raws))
	for i, raw := range raws {
		out = append(out, doc(t, fmt.Sprintf("%s[%d]", prefix, i), kind, raw))
	}
	return out
}

// doc accepts a full policy document (an object with "Statement"), a single
// statement object, or a list of statements; the last two are wrapped in a
// Version 2012-10-17 document.
func doc(t *testing.T, id string, kind model.PolicyKind, raw json.RawMessage) *model.PolicyDocument {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	if m, ok := v.(map[string]any); !ok || m["Statement"] == nil {
		if ok {
			v = []any{m}
		}
		v = map[string]any{"Version": model.Version2012, "Statement": v}
	}
	js, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	d, err := iampolicy.Parse(js, &iampolicy.Options{ID: id, Kind: kind, Placeholders: true}) // the corpus stands in for the normalizer
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return d
}
