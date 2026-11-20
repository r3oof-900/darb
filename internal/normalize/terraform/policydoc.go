package terraform

import (
	"encoding/json"

	"github.com/r3oof-900/clapa/internal/collect/tfraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/iampolicy"
	"github.com/r3oof-900/clapa/internal/model"
)

// policyDocJSON renders data "aws_iam_policy_document" as policy JSON
// (Terraform AWS provider › aws_iam_policy_document: statement, principals,
// not_principals, condition, actions, not_actions, resources, not_resources).
// Merging inputs (source_policy_documents, override_policy_documents) are
// not modelled: they add an unknown allow and deny, never silence.
func (n *norm) policyDocJSON(r *tfraw.Resource) string {
	stmts := []any{}
	for _, st := range r.Attrs.Blocks("statement") {
		stmts = append(stmts, n.statement(r.Root, st))
	}
	incomplete := false
	for _, k := range []string{"source_policy_documents", "override_policy_documents", "source_json", "override_json"} {
		if _, ok := r.Attrs.Get(k); ok {
			n.gap(coverage.KindNotModelled, r, k+" is not modelled; the merged statements are treated as unknown")
			incomplete = true
		}
	}
	version := "2012-10-17"
	if s, ok := r.Attrs.Str("version"); ok {
		version = s
	}
	js, _ := json.Marshal(map[string]any{"Version": version, "Statement": stmts}) // only maps, slices and strings
	if incomplete {
		// The unknown statements are added where the document is parsed,
		// because only then is it known whether it is a resource policy
		// (Principal required) or an identity policy (Principal forbidden).
		n.incomplete[string(js)] = r.Address
	}
	return string(js)
}

// withUnknownStatements appends the unknown allow and deny to a rendered
// policy document that is incomplete.
func (n *norm) withUnknownStatements(text, id string, resourcePolicy bool) string {
	var doc map[string]any
	if json.Unmarshal([]byte(text), &doc) != nil {
		return text
	}
	stmts, _ := doc["Statement"].([]any)
	doc["Statement"] = append(stmts, n.unknownStatements(id, resourcePolicy)...)
	js, _ := json.Marshal(doc)
	return string(js)
}

func (n *norm) statement(root string, st *tfraw.Object) map[string]any {
	s := map[string]any{"Effect": "Allow"}
	for tf, aws := range map[string]string{
		"sid": "Sid", "effect": "Effect", "actions": "Action", "not_actions": "NotAction",
		"resources": "Resource", "not_resources": "NotResource",
	} {
		if v, ok := st.Get(tf); ok {
			s[aws] = n.toJSON(root, v)
		}
	}
	if p := n.principals(root, st.Blocks("principals")); p != nil {
		s["Principal"] = p
	}
	if p := n.principals(root, st.Blocks("not_principals")); p != nil {
		s["NotPrincipal"] = p
	}
	if c := n.conditions(root, st.Blocks("condition")); len(c) > 0 {
		s["Condition"] = c
	}
	return s
}

// principals: type "*" with identifiers ["*"] is the bare "*" principal.
func (n *norm) principals(root string, blocks []*tfraw.Object) any {
	if len(blocks) == 0 {
		return nil
	}
	out := map[string][]any{}
	for _, p := range blocks {
		t, _ := n.str(root, valueOf(p, "type"))
		ids, _ := n.toJSON(root, valueOf(p, "identifiers")).([]any)
		if t == "*" {
			return "*"
		}
		out[t] = append(out[t], ids...)
	}
	return out
}

func (n *norm) conditions(root string, blocks []*tfraw.Object) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, c := range blocks {
		test, _ := n.str(root, valueOf(c, "test"))
		variable, _ := n.str(root, valueOf(c, "variable"))
		if out[test] == nil {
			out[test] = map[string]any{}
		}
		out[test][variable] = n.toJSON(root, valueOf(c, "values"))
	}
	return out
}

func valueOf(o *tfraw.Object, key string) *tfraw.Value {
	v, ok := o.Get(key)
	if !ok {
		return &tfraw.Value{Kind: tfraw.KNull}
	}
	return v
}

// unknownStatements stand for policy content that is not available: an
// allow and a deny that may apply to anything. They make every decision
// they touch UNKNOWN, never ALLOW and never "safe".
func (n *norm) unknownStatements(id string, resourcePolicy bool) []any {
	p := n.placeholder(id)
	allow := map[string]any{"Effect": "Allow", "Action": p, "Resource": p}
	deny := map[string]any{"Effect": "Deny", "Action": p, "Resource": "*"}
	if resourcePolicy {
		allow["Principal"] = map[string]any{"AWS": p}
		deny["Principal"] = map[string]any{"AWS": p}
	}
	return []any{allow, deny}
}

// parsePolicy builds a policy document from text. Text that is missing or
// does not parse becomes an unknown document, and a coverage gap.
func (n *norm) parsePolicy(r *tfraw.Resource, id string, kind model.PolicyKind, text string, ok bool) *model.PolicyDocument {
	s := src(r)
	if from, merged := n.incomplete[text]; ok && merged {
		text = n.withUnknownStatements(text, from+".merged", kind == model.PolicyResource)
	}
	if ok {
		d, err := iampolicy.Parse([]byte(text), &iampolicy.Options{ID: id, Kind: kind, Source: s, Placeholders: true})
		if err == nil {
			return d
		}
		n.gap(coverage.KindParseError, r, id+": "+err.Error())
	} else {
		n.gap(coverage.KindUnresolved, r, id+": policy content is not available statically")
	}
	return n.unknownDoc(id, kind, &s)
}

func (n *norm) unknownDoc(id string, kind model.PolicyKind, s *model.SourceLocation) *model.PolicyDocument {
	js, _ := json.Marshal(map[string]any{
		"Version": model.Version2012, "Statement": n.unknownStatements(id, kind == model.PolicyResource),
	})
	d, _ := iampolicy.Parse(js, &iampolicy.Options{ID: id, Kind: kind, Source: *s, Placeholders: true}) // always valid
	return d
}
