package hclstatic

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/r3oof-900/clapa/internal/collect/tfraw"
	"github.com/r3oof-900/clapa/internal/coverage"
)

// exprValue converts an expression. A wholly known value is returned as a
// literal. Otherwise the expression's structure is kept where it can be:
// objects, lists, templates, jsonencode(...) arguments, and references to
// other resources' attributes (symbolic). Everything else is Unresolved,
// carrying the source text and position, and recorded as a coverage gap.
func (m *rootModule) exprValue(e hclsyntax.Expression, address string) *tfraw.Value {
	if v, ok := known(e, m.ctx); ok {
		return fromCty(v)
	}
	switch x := e.(type) {
	case *hclsyntax.ObjectConsExpr:
		return m.objectCons(x, address)
	case *hclsyntax.TupleConsExpr:
		out := &tfraw.Value{Kind: tfraw.KList}
		for _, item := range x.Exprs {
			out.List = append(out.List, m.exprValue(item, address))
		}
		return out
	case *hclsyntax.TemplateWrapExpr:
		return m.exprValue(x.Wrapped, address)
	case *hclsyntax.TemplateExpr:
		out := &tfraw.Value{Kind: tfraw.KTemplate, Pos: pos(x.SrcRange)}
		for _, p := range x.Parts {
			out.List = append(out.List, m.exprValue(p, address))
		}
		return out
	case *hclsyntax.ParenthesesExpr:
		return m.exprValue(x.Expression, address)
	case *hclsyntax.FunctionCallExpr:
		if x.Name == "jsonencode" && len(x.Args) == 1 {
			v := m.exprValue(x.Args[0], address)
			v.Expr = "jsonencode"
			return v
		}
	case *hclsyntax.ScopeTraversalExpr:
		if ref := traversalRef(x.Traversal); ref != nil {
			return &tfraw.Value{Kind: tfraw.KRef, Ref: ref, Pos: pos(x.SrcRange)}
		}
	}
	return m.unresolved(e, address)
}

func (m *rootModule) objectCons(x *hclsyntax.ObjectConsExpr, address string) *tfraw.Value {
	o := tfraw.NewObject()
	for _, item := range x.Items {
		key, ok := known(item.KeyExpr, m.ctx)
		if !ok || key.Type() != cty.String {
			return m.unresolved(x, address)
		}
		o.Set(key.AsString(), m.exprValue(item.ValueExpr, address))
	}
	return &tfraw.Value{Kind: tfraw.KObject, Obj: o, Pos: pos(x.SrcRange)}
}

func (m *rootModule) unresolved(e hclsyntax.Expression, address string) *tfraw.Value {
	r := e.Range()
	text := strings.TrimSpace(string(r.SliceBytes(m.src[r.Filename])))
	reason := "not resolvable without a plan"
	if refs := e.Variables(); len(refs) > 0 {
		reason = "depends on " + traversalName(refs[0]) + ", which has no known value"
	}
	m.gap(coverage.KindUnresolved, r.Filename, r.Start.Line, address, text+": "+reason)
	return tfraw.Unresolved(text, reason, pos(r))
}

// traversalRef recognises "type.name.attr" and "data.type.name.attr".
// var, local, module outputs, count/each and indexed instances are not
// symbolic references: their value depends on evaluation we do not do.
func traversalRef(t hcl.Traversal) *tfraw.Ref {
	names := make([]string, 0, len(t))
	for _, step := range t {
		switch s := step.(type) {
		case hcl.TraverseRoot:
			names = append(names, s.Name)
		case hcl.TraverseAttr:
			names = append(names, s.Name)
		default:
			return nil // index or splat: an instance of count/for_each
		}
	}
	switch {
	case len(names) == 4 && names[0] == "data":
		return &tfraw.Ref{Address: strings.Join(names[:3], "."), Attr: names[3]}
	case len(names) == 3 && !isScope(names[0]):
		return &tfraw.Ref{Address: names[0] + "." + names[1], Attr: names[2]}
	}
	return nil
}

func isScope(root string) bool {
	switch root {
	case "var", "local", "module", "each", "count", "path", "terraform", "self", "data":
		return true
	}
	return false
}

func traversalName(t hcl.Traversal) string {
	var b strings.Builder
	for i, step := range t {
		switch s := step.(type) {
		case hcl.TraverseRoot:
			b.WriteString(s.Name)
		case hcl.TraverseAttr:
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString(s.Name)
		default:
			b.WriteString("[...]")
		}
	}
	return b.String()
}

func pos(r hcl.Range) tfraw.Pos {
	return tfraw.Pos{File: r.Filename, StartLine: r.Start.Line, EndLine: r.End.Line}
}

// fromCty converts a wholly known cty value.
func fromCty(v cty.Value) *tfraw.Value {
	if v.IsNull() {
		return &tfraw.Value{Kind: tfraw.KNull}
	}
	t := v.Type()
	switch {
	case t == cty.String:
		return tfraw.String(v.AsString())
	case t == cty.Number:
		return &tfraw.Value{Kind: tfraw.KNumber, Str: v.AsBigFloat().Text('f', -1)}
	case t == cty.Bool:
		return &tfraw.Value{Kind: tfraw.KBool, Bool: v.True()}
	case t.IsObjectType() || t.IsMapType():
		o := tfraw.NewObject()
		for it := v.ElementIterator(); it.Next(); {
			k, ev := it.Element()
			o.Set(k.AsString(), fromCty(ev))
		}
		return &tfraw.Value{Kind: tfraw.KObject, Obj: o}
	case t.IsListType() || t.IsTupleType() || t.IsSetType():
		out := &tfraw.Value{Kind: tfraw.KList}
		for it := v.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			out.List = append(out.List, fromCty(ev))
		}
		return out
	}
	return tfraw.Unresolved(fmt.Sprintf("<%s>", t.FriendlyName()), "unsupported value type", tfraw.Pos{})
}
