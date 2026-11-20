package terraform

import (
	"encoding/json"
	"strings"

	"github.com/r3oof-900/clapa/internal/collect/tfraw"
	"github.com/r3oof-900/clapa/internal/model"
)

// placeholder renders an unresolved value; the id is the source expression,
// restricted to a safe alphabet so it cannot break the surrounding JSON or
// the ${...} syntax.
func placeholder(expr string) string {
	var b strings.Builder
	for _, r := range expr {
		if r == '.' || r == '-' || r == '_' || r == '[' || r == ']' || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return model.UnresolvedPlaceholder(b.String())
}

// str renders a value as a string. ok is false when any part is unresolved
// (the string then contains placeholders).
func (n *norm) str(root string, v *tfraw.Value) (string, bool) {
	if v == nil {
		return "", false
	}
	switch v.Kind {
	case tfraw.KString, tfraw.KNumber:
		return v.Str, true
	case tfraw.KBool:
		if v.Bool {
			return "true", true
		}
		return "false", true
	case tfraw.KRef:
		return n.resolveRef(root, v.Ref)
	case tfraw.KTemplate:
		var b strings.Builder
		ok := true
		for _, p := range v.List {
			s, pok := n.str(root, p)
			b.WriteString(s)
			ok = ok && pok
		}
		return b.String(), ok
	case tfraw.KUnresolved, tfraw.KUnknownAfterApply:
		return placeholder(v.Expr), false
	case tfraw.KNull, tfraw.KList, tfraw.KObject:
	}
	return placeholder("<" + kindName(v.Kind) + ">"), false
}

func kindName(k tfraw.Kind) string {
	switch k {
	case tfraw.KNull:
		return "null"
	case tfraw.KList:
		return "list"
	case tfraw.KObject:
		return "object"
	case tfraw.KString, tfraw.KNumber, tfraw.KBool, tfraw.KRef, tfraw.KTemplate, tfraw.KUnresolved, tfraw.KUnknownAfterApply:
	}
	return "value"
}

// resolveRef turns a symbolic reference into the referenced value: an ARN,
// a name, or a rendered policy document. A reference to something not in the
// input is unresolved.
func (n *norm) resolveRef(root string, ref *tfraw.Ref) (string, bool) {
	t := n.lookup(root, ref.Address)
	if t == nil {
		return placeholder(ref.String()), false
	}
	switch ref.Attr {
	case "arn":
		return n.arnOf(t), true
	case "json":
		if t.Type == "aws_iam_policy_document" {
			return n.policyDocJSON(t), true
		}
	case "name", "id", "bucket", "key_id":
		return n.nameLike(t, ref.Attr), true
	}
	if s, ok := t.Attrs.Str(ref.Attr); ok {
		return s, true
	}
	return placeholder(ref.String()), false
}

// nameLike: role/policy "id" is the name; bucket "id" is the bucket name;
// a KMS key "id"/"key_id" is the (pending) key ID.
func (n *norm) nameLike(t *tfraw.Resource, a string) string {
	if t.Type == "aws_kms_key" {
		if s, ok := t.Attrs.Str("key_id"); ok {
			return s
		}
		return pendingID(t)
	}
	if s, ok := t.Attrs.Str(a); ok && a != "id" {
		return s
	}
	return n.nameOf(t)
}

// toJSON converts a value into something encoding/json renders as Terraform's
// jsonencode would, with references resolved and unresolved leaves as
// placeholders.
func (n *norm) toJSON(root string, v *tfraw.Value) any {
	switch v.Kind {
	case tfraw.KNull:
		return nil
	case tfraw.KBool:
		return v.Bool
	case tfraw.KNumber:
		return json.Number(v.Str)
	case tfraw.KList:
		out := make([]any, 0, len(v.List))
		for _, item := range v.List {
			out = append(out, n.toJSON(root, item))
		}
		return out
	case tfraw.KObject:
		out := map[string]any{}
		for _, k := range v.Obj.Keys() {
			item, _ := v.Obj.Get(k)
			out[k] = n.toJSON(root, item)
		}
		return out
	case tfraw.KString, tfraw.KRef, tfraw.KTemplate, tfraw.KUnresolved, tfraw.KUnknownAfterApply:
	}
	s, _ := n.str(root, v)
	return s
}

// policyText renders a policy-valued attribute (a JSON string, jsonencode
// of an object, a heredoc template, or a reference to a policy document).
// ok is false when the content is not available at all.
func (n *norm) policyText(root string, v *tfraw.Value) (text string, ok bool) {
	if v == nil {
		return "", false
	}
	switch v.Kind {
	case tfraw.KObject:
		js, err := json.Marshal(n.toJSON(root, v))
		return string(js), err == nil
	case tfraw.KString, tfraw.KTemplate, tfraw.KRef:
		s, _ := n.str(root, v)
		return s, !strings.HasPrefix(strings.TrimSpace(s), "${clapa:unresolved:")
	case tfraw.KNull, tfraw.KNumber, tfraw.KBool, tfraw.KList, tfraw.KUnresolved, tfraw.KUnknownAfterApply:
	}
	return "", false
}
