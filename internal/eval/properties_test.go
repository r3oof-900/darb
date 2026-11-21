package eval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/r3oof-900/clapa/internal/eval/condition"
	"github.com/r3oof-900/clapa/internal/eval/match"
	"github.com/r3oof-900/clapa/internal/iampolicy"
	"github.com/r3oof-900/clapa/internal/model"
)

// Small vocabularies keep generated policies relevant to generated requests.
var (
	propActions   = []string{"s3:GetObject", "s3:PutObject", "kms:Decrypt", "kms:Encrypt", "iam:PassRole"}
	propActionPat = []string{"*", "s3:*", "s3:Get*", "kms:*", "kms:Decrypt*", "*Object", "iam:PassRole", "kms:Decrypt"}
	propResources = []string{"arn:aws:s3:::data/a.csv", "arn:aws:s3:::data/b/c", "arn:aws:s3:::logs/x", "arn:aws:kms:us-east-1:111122223333:key/k1"}
	propResPat    = []string{"*", "arn:aws:s3:::data/*", "arn:aws:s3:::data/b/*", "arn:aws:s3:::*", "arn:aws:kms:*:*:key/*", "arn:aws:s3:::logs/x"}
	propPrincipal = []any{
		"*",
		map[string]any{"AWS": "arn:aws:iam::111122223333:role/app"},
		map[string]any{"AWS": "111122223333"},
		map[string]any{"AWS": "arn:aws:sts::111122223333:assumed-role/app/s1"},
		map[string]any{"AWS": "444455556666"},
	}
	propConditions = []map[string]any{
		{"Bool": map[string]any{"aws:SecureTransport": "true"}},
		{"StringEquals": map[string]any{"aws:PrincipalTag/team": "payments"}},
		{"StringEquals": map[string]any{"aws:SourceVpce": "vpce-1"}}, // unknown key
		{"IpAddress": map[string]any{"aws:SourceIp": "203.0.113.0/24"}},
	}
)

type genPolicies struct {
	identity [][]map[string]any
	resource [][]map[string]any
	boundary []map[string]any // nil = none
}

func genStatement(t *rapid.T, label string, withPrincipal bool) map[string]any {
	s := map[string]any{
		"Sid":      label,
		"Effect":   rapid.SampledFrom([]string{"Allow", "Allow", "Deny"}).Draw(t, label+"-effect"),
		"Action":   rapid.SliceOfNDistinct(rapid.SampledFrom(propActionPat), 1, 3, rapid.ID[string]).Draw(t, label+"-action"),
		"Resource": rapid.SliceOfNDistinct(rapid.SampledFrom(propResPat), 1, 3, rapid.ID[string]).Draw(t, label+"-resource"),
	}
	if withPrincipal {
		s["Principal"] = rapid.SampledFrom(propPrincipal).Draw(t, label+"-principal")
	}
	if rapid.Bool().Draw(t, label+"-has-condition") {
		s["Condition"] = rapid.SampledFrom(propConditions).Draw(t, label+"-condition")
	}
	return s
}

func genDocs(t *rapid.T, prefix string, maxDocs int, withPrincipal bool) [][]map[string]any {
	n := rapid.IntRange(0, maxDocs).Draw(t, prefix+"-docs")
	docs := make([][]map[string]any, n)
	for i := range docs {
		m := rapid.IntRange(1, 3).Draw(t, fmt.Sprintf("%s%d-stmts", prefix, i))
		for j := range m {
			docs[i] = append(docs[i], genStatement(t, fmt.Sprintf("%s%d_%d", prefix, i, j), withPrincipal))
		}
	}
	return docs
}

func genPolicySet(t *rapid.T) *genPolicies {
	g := &genPolicies{identity: genDocs(t, "id", 3, false), resource: genDocs(t, "res", 2, true)}
	if rapid.Bool().Draw(t, "has-boundary") {
		g.boundary = []map[string]any{} // a boundary may have no statements: it then allows nothing
		for j := range rapid.IntRange(0, 3).Draw(t, "bnd-stmts") {
			g.boundary = append(g.boundary, genStatement(t, fmt.Sprintf("bnd_%d", j), false))
		}
	}
	return g
}

func genRequest(t *rapid.T) *Request {
	return &Request{
		Principal: match.RequestPrincipal{
			Kind: match.KindAssumedRole, ARN: "arn:aws:sts::111122223333:assumed-role/app/s1",
			Account: "111122223333", SourceARN: "arn:aws:iam::111122223333:role/app",
		},
		Action:          rapid.SampledFrom(propActions).Draw(t, "action"),
		Resource:        rapid.SampledFrom(propResources).Draw(t, "resource"),
		ResourceAccount: rapid.SampledFrom([]string{"111122223333", "444455556666", ""}).Draw(t, "resource-account"),
		Context: condition.NewContext(&condition.Input{
			Default: condition.StateAbsent,
			Present: map[string][]string{
				"aws:SecureTransport":   {rapid.SampledFrom([]string{"true", "false"}).Draw(t, "tls")},
				"aws:PrincipalTag/team": {"payments"},
				"aws:SourceIp":          {"203.0.113.9"},
			},
			Unknown: []string{"aws:SourceVpce"},
		}),
	}
}

func mustDoc(t fataler, id string, kind model.PolicyKind, stmts []map[string]any) *model.PolicyDocument {
	js, err := json.Marshal(map[string]any{"Version": model.Version2012, "Statement": stmts})
	if err != nil {
		t.Fatalf("%v", err)
	}
	d, err := iampolicy.Parse(js, &iampolicy.Options{ID: id, Kind: kind, Placeholders: true})
	if err != nil {
		t.Fatalf("%s: %v\n%s", id, err, js)
	}
	return d
}

func (g *genPolicies) build(t fataler) *PolicySet {
	ps := &PolicySet{}
	for i, d := range g.identity {
		ps.Identity = append(ps.Identity, mustDoc(t, fmt.Sprintf("identity[%d]", i), model.PolicyIdentity, d))
	}
	for i, d := range g.resource {
		ps.Resource = append(ps.Resource, mustDoc(t, fmt.Sprintf("resource[%d]", i), model.PolicyResource, d))
	}
	if g.boundary != nil {
		ps.Boundary = mustDoc(t, "boundary", model.PolicyBoundary, g.boundary)
	}
	return ps
}

// fataler is the part of testing.TB and *rapid.T the helpers need.
type fataler interface {
	Fatalf(format string, args ...any)
}

// Property: adding an unconditional Deny never increases access.
func TestPropertyUnconditionalDenyNeverIncreasesAccess(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		req, g := genRequest(t), genPolicySet(t)
		before := Evaluate(req, g.build(t))
		deny := map[string]any{
			"Effect":   "Deny",
			"Action":   rapid.SampledFrom(propActionPat).Draw(t, "deny-action"),
			"Resource": rapid.SampledFrom(propResPat).Draw(t, "deny-resource"),
		}
		g.identity = append(g.identity, []map[string]any{deny})
		after := Evaluate(req, g.build(t))
		if after.Verdict.Grants() > before.Verdict.Grants() {
			t.Fatalf("adding %v raised %s to %s", deny, before.Verdict, after.Verdict)
		}
	})
}

// Property: narrowing the Resource of an Allow statement never increases access.
func TestPropertyNarrowingResourceNeverIncreasesAccess(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		req, g := genRequest(t), genPolicySet(t)
		if len(g.identity) == 0 {
			g.identity = [][]map[string]any{{genStatement(t, "extra", false)}}
		}
		di := rapid.IntRange(0, len(g.identity)-1).Draw(t, "doc")
		si := rapid.IntRange(0, len(g.identity[di])-1).Draw(t, "stmt")
		s := g.identity[di][si]
		if s["Effect"] != "Allow" {
			t.Skip("only Allow statements are narrowed")
		}
		before := Evaluate(req, g.build(t))
		rs, ok := s["Resource"].([]string)
		if !ok {
			t.Fatalf("generated Resource is %T", s["Resource"])
		}
		s["Resource"] = narrow(t, rs)
		after := Evaluate(req, g.build(t))
		if after.Verdict.Grants() > before.Verdict.Grants() {
			t.Fatalf("narrowing raised %s to %s", before.Verdict, after.Verdict)
		}
	})
}

// narrow returns a resource list whose language is a subset of rs's.
func narrow(t *rapid.T, rs []string) []string {
	if len(rs) > 1 {
		i := rapid.IntRange(0, len(rs)-1).Draw(t, "drop")
		return slices.Delete(slices.Clone(rs), i, i+1)
	}
	p := rs[0]
	if strings.HasSuffix(p, "*") {
		return []string{p[:len(p)-1] + "q*"}
	}
	return []string{"arn:aws:s3:::nothing-matches-this"}
}

// Property: evaluation is deterministic and independent of statement and policy order.
func TestPropertyDeterministicAndOrderIndependent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		req, g := genRequest(t), genPolicySet(t)
		a := Evaluate(req, g.build(t))
		if b := Evaluate(req, g.build(t)); !equalDecisions(&a, &b) {
			t.Fatalf("two evaluations differ:\n%+v\n%+v", a, b)
		}
		shuffle := func(label string, docs [][]map[string]any) [][]map[string]any {
			out := rapid.Permutation(docs).Draw(t, label)
			for i := range out {
				out[i] = rapid.Permutation(out[i]).Draw(t, fmt.Sprintf("%s-%d", label, i))
			}
			return out
		}
		g.identity, g.resource = shuffle("identity", g.identity), shuffle("resource", g.resource)
		// Permutation turns an empty slice into nil, which would change the
		// meaning (an empty boundary allows nothing; a nil boundary is none).
		if len(g.boundary) > 0 {
			g.boundary = rapid.Permutation(g.boundary).Draw(t, "boundary")
		}
		c := Evaluate(req, g.build(t))
		if a.Verdict != c.Verdict || !slices.Equal(sids(a.Contributing), sids(c.Contributing)) {
			t.Fatalf("order changed the decision: %s %v vs %s %v", a.Verdict, sids(a.Contributing), c.Verdict, sids(c.Contributing))
		}
	})
}

func sids(refs []StatementRef) []string {
	out := make([]string, 0, len(refs))
	for i := range refs {
		out = append(out, refs[i].Sid)
	}
	slices.Sort(out)
	return out
}

func equalDecisions(a, b *Decision) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// worstCase: whether the request is allowed when every unknown is resolved
// in the attacker's favour (DESIGN.md 6.2).
func worstCase(v Verdict) bool { return v == Allow || v == Unknown }

// Adding a policy whose statements are unknown never lowers the worst case:
// an unknown Allow can only add access, an unknown Deny resolved in the
// attacker's favour does not apply; and an unknown Deny added to an ALLOW
// gives a deny-only UNKNOWN.
func TestPropertyUnknownPolicyNeverLowersWorstCase(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		g := genPolicySet(t)
		req := genRequest(t)
		before := Evaluate(req, g.build(t))
		unknown := map[string]any{"StringEquals": map[string]any{"aws:SourceVpce": "vpce-1"}} // the generated requests leave it unknown
		var stmts []map[string]any
		kind := rapid.SampledFrom([]string{"allow", "deny", "both"}).Draw(t, "unknown-policy")
		if kind != "deny" {
			stmts = append(stmts, map[string]any{"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": unknown})
		}
		if kind != "allow" {
			stmts = append(stmts, map[string]any{"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": unknown})
		}
		ps := g.build(t)
		ps.Identity = append(ps.Identity, mustDoc(t, "unknown-managed", model.PolicyIdentity, stmts))
		after := Evaluate(req, ps)
		if worstCase(before.Verdict) && !worstCase(after.Verdict) {
			t.Fatalf("an unknown policy (%s) lowered the worst case: %s -> %s", kind, before.Verdict, after.Verdict)
		}
		if before.Verdict == Allow && kind == "deny" && (after.Verdict != Unknown || !after.DenyOnly) {
			t.Fatalf("an unknown Deny on an ALLOW: %s deny-only=%v, want a deny-only UNKNOWN", after.Verdict, after.DenyOnly)
		}
	})
}
