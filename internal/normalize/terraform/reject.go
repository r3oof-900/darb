package terraform

import (
	"github.com/r3oof-900/clapa/internal/collect/tfraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/model"
)

// rejectReserved replaces every input value that contains the reserved
// placeholder text with an unresolved value, and reports it as a parse
// error at its file:line (the nearest known position: the value's own, else
// its resource's). Strings, numbers, object keys and template literals are
// checked; the collectors have already decoded HCL's "$$" and backslash-u
// escapes and the plan's JSON escapes, so what is checked is the real text.
// JSON escapes inside a policy string are caught when the policy is parsed
// (iampolicy.ErrReservedText).
func (n *norm) rejectReserved(m *tfraw.Module) {
	for _, r := range m.Resources {
		for _, k := range r.Attrs.Keys() {
			v, _ := r.Attrs.Get(k)
			n.rejectValue(v, r.Pos, r.Address, k)
		}
	}
	for _, p := range m.Providers {
		for _, v := range []*tfraw.Value{p.Region, p.Account} {
			if v != nil {
				n.rejectValue(v, v.Pos, "provider."+p.Key, "")
			}
		}
	}
}

func (n *norm) rejectValue(v *tfraw.Value, at tfraw.Pos, address, path string) {
	if v.Pos.File != "" {
		at = v.Pos
	}
	bad := false
	switch v.Kind {
	case tfraw.KString, tfraw.KNumber:
		bad = model.ContainsUnresolved(v.Str)
	case tfraw.KObject:
		for _, k := range v.Obj.Keys() {
			child, _ := v.Obj.Get(k)
			bad = bad || model.ContainsUnresolved(k)
			n.rejectValue(child, at, address, path+"."+k)
		}
	case tfraw.KList, tfraw.KTemplate:
		for _, item := range v.List {
			n.rejectValue(item, at, address, path)
		}
	case tfraw.KNull, tfraw.KBool, tfraw.KRef, tfraw.KUnresolved, tfraw.KUnknownAfterApply:
	}
	if !bad {
		return
	}
	n.rec.Add(&coverage.Gap{
		Kind: coverage.KindParseError, Source: Name, File: at.File, Line: at.StartLine, Address: address,
		Detail: path + " contains the reserved text " + model.UnresolvedPrefix + "...}: rejected as invalid input, treated as unknown",
	})
	*v = *tfraw.Unresolved("rejected input", "contains reserved text", at)
}
