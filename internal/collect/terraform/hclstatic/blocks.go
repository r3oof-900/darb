package hclstatic

import (
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/r3oof-900/darb/internal/collect/tfraw"
	"github.com/r3oof-900/darb/internal/coverage"
)

// metaArgs are Terraform meta-arguments, not resource attributes.
func isMetaArg(name string) bool {
	switch name {
	case "count", "for_each", "provider", "depends_on":
		return true
	}
	return false
}

func (m *rootModule) resources() []*tfraw.Resource {
	var out []*tfraw.Resource
	for _, b := range m.blocks {
		if (b.Type == "resource" || b.Type == "data") && len(b.Labels) == 2 {
			out = append(out, m.resource(b))
		}
	}
	return out
}

func (m *rootModule) resource(b *hclsyntax.Block) *tfraw.Resource {
	address := b.Labels[0] + "." + b.Labels[1]
	mode := "managed"
	if b.Type == "data" {
		address, mode = "data."+address, "data"
	}
	r := &tfraw.Resource{
		Address: address, Mode: mode, Type: b.Labels[0], Name: b.Labels[1], Root: m.prefix,
		Provider: providerKey(b), Pos: pos(b.Range()),
	}
	if _, ok := b.Body.Attributes["count"]; ok {
		r.Index = "[*]"
	}
	if _, ok := b.Body.Attributes["for_each"]; ok {
		r.Index = "[*]"
	}
	if r.Index != "" {
		r.Address += r.Index
		m.gap(coverage.KindUnresolved, b.TypeRange.Filename, b.TypeRange.Start.Line, address,
			"count/for_each instances are expanded only from a plan")
	}
	r.Attrs = m.body(b.Body, address)
	return r
}

// providerKey: "aws.alias" from the provider meta-argument, else the type's provider.
func providerKey(b *hclsyntax.Block) string {
	if a, ok := b.Body.Attributes["provider"]; ok {
		if st, ok := a.Expr.(*hclsyntax.ScopeTraversalExpr); ok {
			return traversalName(st.Traversal)
		}
	}
	name, _, _ := strings.Cut(b.Labels[0], "_")
	return name
}

// body converts attributes and nested blocks. Repeated nested blocks of one
// type become a list of objects, matching plan JSON.
func (m *rootModule) body(body *hclsyntax.Body, address string) *tfraw.Object {
	o := tfraw.NewObject()
	for _, a := range sortedAttrs(body.Attributes) {
		if !isMetaArg(a.Name) {
			o.Set(a.Name, m.exprValue(a.Expr, address))
		}
	}
	blocks := map[string]*tfraw.Value{}
	var order []string
	for _, nb := range body.Blocks {
		if nb.Type == "lifecycle" {
			continue
		}
		if nb.Type == "dynamic" {
			m.gap(coverage.KindUnresolved, nb.TypeRange.Filename, nb.TypeRange.Start.Line, address,
				"dynamic \""+strings.Join(nb.Labels, "")+"\" blocks are expanded only from a plan")
			o.Set(strings.Join(nb.Labels, ""), tfraw.Unresolved("dynamic block", "dynamic blocks are not expanded statically", pos(nb.Range())))
			continue
		}
		if _, ok := blocks[nb.Type]; !ok {
			blocks[nb.Type] = &tfraw.Value{Kind: tfraw.KList}
			order = append(order, nb.Type)
		}
		obj := m.body(nb.Body, address)
		if len(nb.Labels) > 0 {
			obj.Set("__label", tfraw.String(nb.Labels[0]))
		}
		blocks[nb.Type].List = append(blocks[nb.Type].List, &tfraw.Value{Kind: tfraw.KObject, Obj: obj, Pos: pos(nb.Range())})
	}
	slices.Sort(order)
	for _, t := range order {
		o.Set(t, blocks[t])
	}
	return o
}

func (m *rootModule) providers() []*tfraw.Provider {
	var out []*tfraw.Provider
	for _, b := range m.blocks {
		if b.Type != "provider" || len(b.Labels) != 1 || b.Labels[0] != "aws" {
			continue
		}
		attrs := m.body(b.Body, "provider.aws")
		key := "aws"
		if alias, ok := attrs.Str("alias"); ok {
			key = "aws." + alias
		}
		p := &tfraw.Provider{Key: m.prefix + ":" + key}
		p.Region, _ = attrs.Get("region")
		p.Account = providerAccount(attrs)
		out = append(out, p)
	}
	return out
}

// providerAccount: the single allowed_account_ids entry, when there is one.
func providerAccount(attrs *tfraw.Object) *tfraw.Value {
	v, ok := attrs.Get("allowed_account_ids")
	if ok && v.Kind == tfraw.KList && len(v.List) == 1 {
		return v.List[0]
	}
	return nil
}
