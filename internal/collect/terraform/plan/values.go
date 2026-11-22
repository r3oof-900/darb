package plan

import (
	"fmt"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/r3oof-900/darb/internal/collect/tfraw"
	"github.com/r3oof-900/darb/internal/coverage"
)

// object converts planned attribute values, consulting after_unknown and the
// configuration's references for values only known after apply.
func (c *converter) object(vals map[string]any, unknown any, cfg *tfjson.ConfigResource, r *tfraw.Resource) *tfraw.Object {
	o := tfraw.NewObject()
	unk, _ := unknown.(map[string]any)
	var exprs map[string]*tfjson.Expression
	if cfg != nil {
		exprs = cfg.Expressions
	}
	for k, v := range vals {
		o.Set(k, c.value(v, unk[k], exprs[k], r, k))
	}
	for k, u := range unk { // unknown attributes may be absent from the values
		if _, present := vals[k]; !present {
			o.Set(k, c.value(nil, u, exprs[k], r, k))
		}
	}
	return o
}

func (c *converter) value(v, unknown any, expr *tfjson.Expression, r *tfraw.Resource, path string) *tfraw.Value {
	if b, ok := unknown.(bool); ok && b {
		return c.unknownValue(expr, r, path)
	}
	switch x := v.(type) {
	case nil:
		return &tfraw.Value{Kind: tfraw.KNull}
	case string:
		return tfraw.String(x)
	case bool:
		return &tfraw.Value{Kind: tfraw.KBool, Bool: x}
	case float64:
		return &tfraw.Value{Kind: tfraw.KNumber, Str: fmt.Sprint(x)}
	case map[string]any:
		return &tfraw.Value{Kind: tfraw.KObject, Obj: c.object(x, unknown, nested(expr, 0), r)}
	case []any:
		return c.list(x, unknown, expr, r, path)
	}
	return tfraw.Unresolved(fmt.Sprint(v), "unsupported plan value type", tfraw.Pos{File: c.file})
}

func (c *converter) list(items []any, unknown any, expr *tfjson.Expression, r *tfraw.Resource, path string) *tfraw.Value {
	unk, _ := unknown.([]any)
	out := &tfraw.Value{Kind: tfraw.KList}
	for i, item := range items {
		var u any
		if i < len(unk) {
			u = unk[i]
		}
		if m, ok := item.(map[string]any); ok {
			um, _ := u.(map[string]any)
			out.List = append(out.List, &tfraw.Value{Kind: tfraw.KObject, Obj: c.object(m, um, nested(expr, i), r)})
			continue
		}
		out.List = append(out.List, c.value(item, u, nil, r, fmt.Sprintf("%s[%d]", path, i)))
	}
	return out
}

// nested returns a ConfigResource-shaped view of the i-th nested block's
// expressions, so references inside blocks are found too.
func nested(expr *tfjson.Expression, i int) *tfjson.ConfigResource {
	if expr == nil || expr.ExpressionData == nil || i >= len(expr.NestedBlocks) {
		return nil
	}
	return &tfjson.ConfigResource{Expressions: expr.NestedBlocks[i]}
}

// unknownValue: a value only known after apply. If the configuration
// expression references exactly one resource attribute, keep it as a
// symbolic reference; otherwise it is unknown, and recorded as a gap.
func (c *converter) unknownValue(expr *tfjson.Expression, r *tfraw.Resource, path string) *tfraw.Value {
	if ref := attrRef(expr, r.Module); ref != nil {
		// [each.key] and [count.index] name this instance's own key exactly,
		// and so does [each.value] when the for_each source is a set.
		if ref.Selector == tfraw.SelectEachValue && r.Index != "" {
			if c.eachValueIsKey(r) {
				ref.Selector = tfraw.SelectEachKey
			}
		}
		if (ref.Selector == tfraw.SelectEachKey || ref.Selector == tfraw.SelectCountIndex) && r.Index != "" {
			ref.Address, ref.Selector = ref.Address+"["+r.Index+"]", ""
		}
		return &tfraw.Value{Kind: tfraw.KRef, Ref: ref, Pos: tfraw.Pos{File: c.file}}
	}
	detail, reason := path+" is only known after apply", ""
	if expr == nil {
		detail, reason = detail+" ("+tfraw.ReasonComputed+")", tfraw.ReasonComputed
	}
	c.rec.Add(&coverage.Gap{Kind: coverage.KindUnknownAfterApply, Source: Name, File: c.file, Address: r.Address, Detail: detail})
	return &tfraw.Value{Kind: tfraw.KUnknownAfterApply, Expr: path, Reason: reason, Pos: tfraw.Pos{File: c.file}}
}

// attrRef picks the attribute reference ("type.name.attr" or
// "data.type.name.attr") among an expression's references. Terraform lists
// both the attribute and the bare resource; more than one distinct attribute
// means a computed expression, which is not a plain reference.
//
// An index by expression is recorded differently: aws_iam_role.r[each.key].id
// appears only as ["aws_iam_role.r", "each.key"] (verified with Terraform
// 1.17 "terraform show -json"). That becomes an instance reference with a
// Selector, and the normalizer decides which instance it can name.
func attrRef(expr *tfjson.Expression, module string) *tfraw.Ref {
	if expr == nil || expr.ExpressionData == nil {
		return nil
	}
	var refs refSet
	for _, ref := range expr.References {
		if !refs.add(ref, module) {
			return nil
		}
	}
	return refs.result()
}

// refSet classifies an expression's references.
type refSet struct {
	attr, bare *tfraw.Ref // "type.name.attr" and "type.name"
	selectors  []string   // each.*, count.*, var.*, local.*
}

// add records one reference; false means the expression is not a plain
// reference (two attributes, two resources, a module output).
func (s *refSet) add(ref, module string) bool {
	parts := strings.Split(ref, ".")
	n := 3
	if parts[0] == "data" {
		n = 4
	}
	switch {
	case parts[0] == "module":
		return false
	case parts[0] == "each" || parts[0] == "count" || parts[0] == "var" || parts[0] == "local":
		s.selectors = append(s.selectors, ref)
	case len(parts) == n-1:
		cand := &tfraw.Ref{Address: join(module, ref)}
		if s.bare != nil && s.bare.Address != cand.Address {
			return false
		}
		s.bare = cand
	case len(parts) == n:
		cand := &tfraw.Ref{Address: join(module, strings.Join(parts[:n-1], ".")), Attr: parts[n-1]}
		if s.attr != nil && s.attr.String() != cand.String() {
			return false
		}
		s.attr = cand
	}
	return true
}

func (s *refSet) result() *tfraw.Ref {
	if s.attr != nil {
		// Anything besides the attribute and its own resource makes it a
		// computed expression ("${aws_s3_bucket.b.arn}/${var.p}").
		if len(s.selectors) > 0 || (s.bare != nil && s.bare.Address != s.attr.Address) {
			return nil
		}
		return s.attr
	}
	if s.bare == nil || len(s.selectors) == 0 {
		return nil
	}
	// Only the bare resource and an index expression: an instance reference.
	s.bare.Selector = strings.Join(s.selectors, ",")
	return s.bare
}

// eachValueIsKey reports whether each.value of r equals its key: its
// for_each source is verifiably a set. Otherwise the reason is a gap.
func (c *converter) eachValueIsKey(r *tfraw.Resource) bool {
	why := "no configuration directory was given with the plan, so whether its for_each source is a set cannot be verified"
	if c.src != nil {
		kind, reason := c.src.kind(r.Module, r.Type, r.Name)
		if kind == forEachSet {
			return true
		}
		why = reason
	}
	c.rec.Add(&coverage.Gap{
		Kind: coverage.KindUnresolved, Source: Name, File: c.file, Address: r.Address,
		Detail: "each.value is not known to equal each.key: " + why,
	})
	return false
}
