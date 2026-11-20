package plan

import (
	"fmt"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/r3oof-900/clapa/internal/collect/tfraw"
	"github.com/r3oof-900/clapa/internal/coverage"
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
		return &tfraw.Value{Kind: tfraw.KRef, Ref: ref, Pos: tfraw.Pos{File: c.file}}
	}
	c.rec.Add(&coverage.Gap{
		Kind: coverage.KindUnknownAfterApply, Source: Name, File: c.file, Address: r.Address,
		Detail: path + " is only known after apply",
	})
	return &tfraw.Value{Kind: tfraw.KUnknownAfterApply, Expr: path, Pos: tfraw.Pos{File: c.file}}
}

// attrRef picks the attribute reference ("type.name.attr" or
// "data.type.name.attr") among an expression's references. Terraform lists
// both the attribute and the bare resource; more than one distinct attribute
// means a computed expression, which is not a plain reference.
func attrRef(expr *tfjson.Expression, module string) *tfraw.Ref {
	if expr == nil || expr.ExpressionData == nil {
		return nil
	}
	var found *tfraw.Ref
	for _, ref := range expr.References {
		parts := strings.Split(ref, ".")
		n := 3
		if parts[0] == "data" {
			n = 4
		}
		if len(parts) != n || parts[0] == "var" || parts[0] == "local" || parts[0] == "module" {
			continue
		}
		cand := &tfraw.Ref{Address: join(module, strings.Join(parts[:n-1], ".")), Attr: parts[n-1]}
		if found != nil && found.String() != cand.String() {
			return nil
		}
		found = cand
	}
	return found
}
