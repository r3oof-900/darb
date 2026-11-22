package patch

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/r3oof-900/darb/internal/model"
)

type resolver func(string) (value, error)

// hclString quotes s as an HCL string: escapes, and ${ / %{ written so
// Terraform does not interpolate them.
func hclString(s string) string {
	b, _ := json.Marshal(s)
	q := string(b)
	q = strings.ReplaceAll(q, "${", "$${")
	return strings.ReplaceAll(q, "%{", "%%{")
}

// hclValue: a reference stays bare; with a suffix it is interpolated.
func hclValue(v value) string {
	switch {
	case v.ref != "" && v.suffix == "":
		return v.ref
	case v.ref != "":
		return `"${` + v.ref + `}` + strings.Trim(hclString(v.suffix), `"`) + `"`
	}
	return hclString(v.lit)
}

// jsonValue is a JSON string for a heredoc: a reference is interpolated.
func jsonValue(v value) string {
	if v.ref != "" {
		b, _ := json.Marshal(v.suffix)
		return `"${` + v.ref + `}` + strings.Trim(string(b), `"`) + `"`
	}
	b, _ := json.Marshal(v.lit)
	return strings.ReplaceAll(strings.ReplaceAll(string(b), "${", "$${"), "%{", "%%{")
}

func list(vals []string, res resolver, render func(value) string) (string, error) {
	out := make([]string, len(vals))
	for i, v := range vals {
		r, err := res(v)
		if err != nil {
			return "", err
		}
		out[i] = render(r)
	}
	return "[" + strings.Join(out, ", ") + "]", nil
}

// style is how a form writes values, keys and objects.
type style struct {
	res    resolver
	render func(value) string
	key    func(string) string
	obj    func([][2]string) string
}

// statementParts are a statement's elements as key/value pairs in a style.
func statementParts(s *model.StatementInput, st *style) ([][2]string, error) {
	var parts [][2]string
	add := func(k, v string) { parts = append(parts, [2]string{k, v}) }
	if s.Sid != "" {
		add("Sid", st.render(value{lit: s.Sid}))
	}
	add("Effect", st.render(value{lit: s.Effect.String()}))
	if s.Principal != nil {
		p, err := st.principal(s.Principal)
		if err != nil {
			return nil, err
		}
		add("Principal", p)
	}
	if len(s.Action) > 0 {
		l, _ := list(s.Action, func(v string) (value, error) { return value{lit: v}, nil }, st.render)
		add("Action", l)
	}
	if len(s.Resource) > 0 {
		l, err := list(s.Resource, st.res, st.render)
		if err != nil {
			return nil, err
		}
		add("Resource", l)
	}
	if len(s.Conditions) > 0 {
		c, err := st.conditions(s.Conditions)
		if err != nil {
			return nil, err
		}
		add("Condition", c)
	}
	return parts, nil
}

// principal writes { AWS = [...] }; the generator writes AWS principals only.
func (st *style) principal(spec *model.PrincipalSpec) (string, error) {
	var refs []string
	for _, r := range spec.Refs() {
		if r.Type != model.PrincipalAWS {
			return "", fmt.Errorf("a %s principal cannot be written by the generator", r.Type)
		}
		refs = append(refs, r.Value)
	}
	l, err := list(refs, st.res, st.render)
	if err != nil {
		return "", err
	}
	return st.obj([][2]string{{st.key("AWS"), l}}), nil
}

// conditions writes { Operator = { key = [...] } }, operators in order.
func (st *style) conditions(cs []model.Condition) (string, error) {
	byOp := map[string][][2]string{}
	var ops []string
	for i := range cs {
		c := &cs[i]
		l, err := list(c.Values(), st.res, st.render)
		if err != nil {
			return "", err
		}
		if _, seen := byOp[c.Operator()]; !seen {
			ops = append(ops, c.Operator())
		}
		byOp[c.Operator()] = append(byOp[c.Operator()], [2]string{st.key(c.Key()), l})
	}
	cond := make([][2]string, 0, len(ops))
	for _, op := range ops {
		cond = append(cond, [2]string{st.key(op), st.obj(byOp[op])})
	}
	return st.obj(cond), nil
}

// hclStatement renders a statement as an HCL object literal on one line,
// for jsonencode.
func hclStatement(s *model.StatementInput, res resolver) (string, error) {
	key := func(k string) string {
		if isIdent(k) {
			return k
		}
		return hclString(k)
	}
	obj := func(kv [][2]string) string {
		items := make([]string, len(kv))
		for i, p := range kv {
			items[i] = p[0] + " = " + p[1]
		}
		return "{ " + strings.Join(items, ", ") + " }"
	}
	parts, err := statementParts(s, &style{res: res, render: hclValue, key: key, obj: obj})
	if err != nil {
		return "", err
	}
	for i := range parts {
		parts[i][0] = key(parts[i][0])
	}
	return obj(parts), nil
}

// statementJSON renders a statement as a JSON object on one line.
func statementJSON(s *model.StatementInput, res resolver) (string, error) {
	key := func(k string) string { b, _ := json.Marshal(k); return string(b) }
	obj := func(kv [][2]string) string {
		items := make([]string, len(kv))
		for i, p := range kv {
			items[i] = p[0] + ": " + p[1]
		}
		return "{" + strings.Join(items, ", ") + "}"
	}
	parts, err := statementParts(s, &style{res: res, render: jsonValue, key: key, obj: obj})
	if err != nil {
		return "", err
	}
	for i := range parts {
		parts[i][0] = key(parts[i][0])
	}
	return obj(parts), nil
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		ok := r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && (r >= '0' && r <= '9' || r == '-')
		if !ok {
			return false
		}
	}
	return true
}

// dataStatement renders a statement as a `statement { ... }` block of a
// data "aws_iam_policy_document", with indent and the file's newline;
// the "=" of each block's attributes are aligned (terraform fmt).
func dataStatement(s *model.StatementInput, res resolver, indent, step, nl string) (string, error) {
	type attr struct{ k, v string }
	var lines []string
	block := func(name, depth string, attrs []attr) {
		w := 0
		for _, a := range attrs {
			w = max(w, len(a.k))
		}
		lines = append(lines, depth+name+" {")
		for _, a := range attrs {
			lines = append(lines, depth+step+a.k+strings.Repeat(" ", w-len(a.k))+" = "+a.v)
		}
	}
	var top []attr
	if s.Sid != "" {
		top = append(top, attr{"sid", hclString(s.Sid)})
	}
	top = append(top, attr{"effect", hclString(s.Effect.String())})
	acts, _ := list(s.Action, func(v string) (value, error) { return value{lit: v}, nil }, hclValue)
	top = append(top, attr{"actions", acts})
	if len(s.Resource) > 0 {
		r, err := list(s.Resource, res, hclValue)
		if err != nil {
			return "", err
		}
		top = append(top, attr{"resources", r})
	}
	block("statement", indent, top)
	inner := indent + step
	if s.Principal != nil {
		var ids []string
		for _, r := range s.Principal.Refs() {
			ids = append(ids, r.Value)
		}
		l, err := list(ids, res, hclValue)
		if err != nil {
			return "", err
		}
		block("principals", inner, []attr{{"type", hclString("AWS")}, {"identifiers", l}})
		lines = append(lines, inner+"}")
	}
	for i := range s.Conditions {
		c := &s.Conditions[i]
		l, err := list(c.Values(), res, hclValue)
		if err != nil {
			return "", err
		}
		block("condition", inner, []attr{{"test", hclString(c.Operator())}, {"variable", hclString(c.Key())}, {"values", l}})
		lines = append(lines, inner+"}")
	}
	lines = append(lines, indent+"}")
	return strings.Join(lines, nl), nil
}
