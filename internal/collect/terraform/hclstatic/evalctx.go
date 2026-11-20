package hclstatic

import (
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// functions is the whitelist from docs/DESIGN.md section 4.1. Nothing else
// is callable; calls to other functions make the value unresolved.
// Note: Terraform's replace() also accepts /regex/ patterns; stdlib's is a
// plain substring replace, so a regex pattern is simply not matched there.
func functions() map[string]function.Function {
	return map[string]function.Function{
		"jsonencode": stdlib.JSONEncodeFunc,
		"format":     stdlib.FormatFunc,
		"concat":     stdlib.ConcatFunc,
		"merge":      stdlib.MergeFunc,
		"lookup":     stdlib.LookupFunc,
		"join":       stdlib.JoinFunc,
		"replace":    stdlib.ReplaceFunc,
		"lower":      stdlib.LowerFunc,
		"upper":      stdlib.UpperFunc,
		"tostring":   stdlib.MakeToFunc(cty.String),
		"tolist":     stdlib.MakeToFunc(cty.List(cty.DynamicPseudoType)),
		"toset":      stdlib.MakeToFunc(cty.Set(cty.DynamicPseudoType)),
	}
}

// evaluate builds the evaluation context: variables (defaults overridden by
// auto-loaded tfvars) and locals, resolved iteratively because locals may
// refer to each other. Values that cannot be resolved are simply absent, so
// any expression using them fails and becomes Unresolved.
func (m *rootModule) evaluate() {
	vars := map[string]cty.Value{}
	for name, def := range m.vars {
		if def == nil {
			continue // no default: unresolved unless a tfvars file sets it
		}
		if v, ok := known(def.Expr, nil); ok {
			vars[name] = v
		}
	}
	for _, a := range m.tfvars {
		if v, ok := known(a.Expr, nil); ok {
			vars[a.Name] = v
		}
	}
	m.ctx = &hcl.EvalContext{Variables: map[string]cty.Value{"var": cty.ObjectVal(vars)}, Functions: functions()}
	m.resolveLocals()
}

func (m *rootModule) resolveLocals() {
	locals := map[string]cty.Value{}
	names := make([]string, 0, len(m.locals))
	for n := range m.locals {
		names = append(names, n)
	}
	slices.Sort(names)
	for range len(names) + 1 { // each pass resolves at least one more local, or stops
		progress := false
		for _, n := range names {
			if _, done := locals[n]; done {
				continue
			}
			m.ctx.Variables["local"] = cty.ObjectVal(locals)
			if v, ok := known(m.locals[n].Expr, m.ctx); ok {
				locals[n], progress = v, true
			}
		}
		if !progress {
			break
		}
	}
	m.ctx.Variables["local"] = cty.ObjectVal(locals)
}

// known evaluates e and reports whether it produced a wholly known value.
func known(e hclsyntax.Expression, ctx *hcl.EvalContext) (cty.Value, bool) {
	v, diags := e.Value(ctx)
	if diags.HasErrors() || !v.IsWhollyKnown() {
		return cty.NilVal, false
	}
	return v, true
}
