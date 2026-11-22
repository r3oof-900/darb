package patch

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/remediate"
)

// errTODO marks an edit that cannot be placed exactly; the message says why
// and what to change by hand.
var errTODO = errors.New("TODO")

func todo(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errTODO}, args...)...)
}

// tfFile is a parsed Terraform file being edited.
type tfFile struct {
	*text
	body *hclsyntax.Body
	dir  string
}

func parseTF(p string, data []byte) (*tfFile, error) {
	t := newText(p, data)
	f, diags := hclsyntax.ParseConfig(t.src, p, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("patch: %s does not parse: %s", p, diags.Error())
	}
	body, ok := f.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("patch: %s: not native HCL syntax", p)
	}
	return &tfFile{text: t, body: body, dir: path.Dir(p)}, nil
}

// validTF: the edited bytes parse again (DESIGN.md §9.3).
func validTF(p string, data []byte) error {
	_, err := parseTF(p, data)
	return err
}

func (f *tfFile) srcOf(r hcl.Range) string { return string(f.src[r.Start.Byte:r.End.Byte]) }

// block finds `<kind> "<type>" "<name>"` in the file.
func (f *tfFile) block(kind, typ, name string) *hclsyntax.Block {
	for _, b := range f.body.Blocks {
		if b.Type == kind && len(b.Labels) == 2 && b.Labels[0] == typ && b.Labels[1] == name {
			return b
		}
	}
	return nil
}

// resourceAddr splits a local address "type.name" or "type.name[key]":
// indexed when the resource has count or for_each.
func resourceAddr(local string) (typ, name string, indexed, ok bool) {
	typ, name, ok = strings.Cut(local, ".")
	if i := strings.IndexByte(name, '['); i >= 0 {
		name, indexed = name[:i], true
	}
	return typ, name, indexed, ok && !strings.Contains(name, ".")
}

// definition finds the file that defines a resource: the source file
// itself, or, for a resource read from a plan, the one .tf file of the
// configurations that has the block.
func (p *patcher) definition(src *model.SourceLocation, typ, name string) (*tfFile, *hclsyntax.Block, error) {
	if strings.HasSuffix(src.File(), ".tf") {
		f, err := p.tf(src.File())
		if err != nil {
			return nil, nil, err
		}
		if b := f.block("resource", typ, name); b != nil {
			return f, b, nil
		}
		return nil, nil, fmt.Errorf("patch: %s is not in %s", src.Address(), src.File())
	}
	var found []string
	for _, dir := range p.opts.ConfigDirs {
		files, _ := p.src.Walk(dir)
		for _, file := range files {
			if f, err := p.tf(file); err == nil && f.block("resource", typ, name) != nil {
				found = append(found, file)
			}
		}
	}
	if len(found) != 1 {
		return nil, nil, todo("%s was read from a plan and %d configuration files define resource %q %q: edit it by hand", src.Address(), len(found), typ, name)
	}
	f, _ := p.tf(found[0])
	b := f.block("resource", typ, name)
	return f, b, nil
}

// keyName is an object item's key: a bare name or a literal string.
func keyName(item *hclsyntax.ObjectConsItem) string {
	v, diags := item.KeyExpr.Value(nil)
	if diags.HasErrors() || v.Type() != cty.String || !v.IsKnown() {
		return ""
	}
	return v.AsString()
}

func objectItem(obj *hclsyntax.ObjectConsExpr, name string) *hclsyntax.ObjectConsItem {
	for i := range obj.Items {
		if keyName(&obj.Items[i]) == name {
			return &obj.Items[i]
		}
	}
	return nil
}

// pctx renders values for one policy of one file.
type pctx struct {
	p       *patcher
	f       *tfFile
	mod     string
	doc     *model.PolicyDocument
	indexed bool // the resource has count or for_each
}

// policyEdits are the edits of one policy document.
type policyEdits struct {
	doc   *model.PolicyDocument
	edits []remediate.Edit
}

// tfPolicy places the edits of a policy defined in Terraform: the resource
// (or role) attribute that holds it, written as jsonencode(...), a heredoc,
// or a data "aws_iam_policy_document" reference.
func (p *patcher) tfPolicy(pe *policyEdits) error {
	src := pe.doc.Source()
	mod, local := moduleOf(src.Address())
	typ, name, indexed, ok := resourceAddr(local)
	if !ok {
		return todo("%s is not a resource address; %s", src.Address(), p.byHand(pe))
	}
	if indexed && hasAdd(pe) {
		return todo("%s is an instance of a resource with count or for_each: a statement added there applies to every instance; %s", src.Address(), p.byHand(pe))
	}
	f, b, err := p.definition(src, typ, name)
	if err != nil {
		return err
	}
	attrName := "policy"
	if strings.HasSuffix(pe.doc.ID(), ".assume_role_policy") {
		attrName = "assume_role_policy"
	}
	attr := b.Body.Attributes[attrName]
	if attr == nil {
		return todo("%s has no %s attribute to edit; %s", src.Address(), attrName, p.byHand(pe))
	}
	if mod != "" && hasAdd(pe) {
		return todo("%s is defined in %s, used by every call of the module; %s", src.Address(), mod, p.byHand(pe))
	}
	pc := &pctx{p: p, f: f, mod: mod, doc: pe.doc, indexed: indexed}
	return pc.policyForm(attr, pe)
}

// policyForm edits the policy in the form its attribute is written in.
func (c *pctx) policyForm(attr *hclsyntax.Attribute, pe *policyEdits) error {
	where := c.doc.Source().Address() + "." + attr.Name
	switch e := attr.Expr.(type) {
	case *hclsyntax.FunctionCallExpr:
		if e.Name != "jsonencode" || len(e.Args) != 1 {
			return todo("%s is %s(...), not jsonencode: %s", where, e.Name, c.p.byHand(pe))
		}
		obj, ok := e.Args[0].(*hclsyntax.ObjectConsExpr)
		if !ok {
			return todo("%s: jsonencode of a value that is not an object literal; %s", where, c.p.byHand(pe))
		}
		return c.jsonencode(obj, pe.edits)
	case *hclsyntax.TemplateExpr:
		if !strings.HasPrefix(c.f.srcOf(e.SrcRange), "<<") {
			return todo("%s is a quoted string; rewrite it as jsonencode or a heredoc, then %s", where, c.p.byHand(pe))
		}
		return c.heredoc(e, pe.edits)
	case *hclsyntax.ScopeTraversalExpr:
		ref := c.f.srcOf(e.SrcRange)
		if dname, ok := strings.CutPrefix(ref, "data.aws_iam_policy_document."); ok && strings.HasSuffix(dname, ".json") {
			return c.dataDocument(strings.TrimSuffix(dname, ".json"), pe.edits)
		}
		return todo("%s comes from %s; change the policy where %s is defined: %s", where, ref, ref, c.p.byHand(pe))
	}
	return todo("%s is not a policy literal; %s", where, c.p.byHand(pe))
}

func hasAdd(pe *policyEdits) bool {
	return slices.ContainsFunc(pe.edits, func(e remediate.Edit) bool { return e.Op == remediate.OpAddStatement })
}

// byHand describes the edits for a TODO.
func (p *patcher) byHand(pe *policyEdits) string {
	var parts []string
	for i := range pe.edits {
		e := &pe.edits[i]
		switch e.Op {
		case remediate.OpAddStatement:
			js, _ := statementJSON(e.Statement, func(v string) (value, error) { return value{lit: v}, nil })
			parts = append(parts, "add the statement "+js)
		case remediate.OpRemoveValues:
			parts = append(parts, fmt.Sprintf("remove %s from the %s of statement %d", strings.Join(e.Values, ", "), e.Element, e.Index))
		case remediate.OpRemoveStatement:
			parts = append(parts, fmt.Sprintf("remove statement %d", e.Index))
		case remediate.OpSetValues:
			parts = append(parts, fmt.Sprintf("set the %s of statement %d to %s", e.Element, e.Index, strings.Join(e.Values, ", ")))
		case remediate.OpNodeMetadata, remediate.OpRemoveHostNetwork, remediate.OpRemoveExposure, remediate.OpRestrictPublic, remediate.OpDisableTokenMount, remediate.OpRemoveSecretRef, remediate.OpDetachPolicy:
		}
	}
	return "by hand: " + strings.Join(parts, "; ")
}

func (c *pctx) resolve(v string) (value, error) { return c.p.refs.resolve(v, c.f.dir, c.mod) }

// eval evaluates a string expression of the policy with the input's
// values; false (and why) when it depends on something the input does not
// fix (a variable, a module input, each.value).
func (c *pctx) eval(e hclsyntax.Expression) (s string, ok bool, why string) {
	switch x := e.(type) {
	case *hclsyntax.LiteralValueExpr:
		if x.Val.Type() == cty.String && x.Val.IsKnown() {
			return x.Val.AsString(), true, ""
		}
	case *hclsyntax.TemplateWrapExpr:
		return c.eval(x.Wrapped)
	case *hclsyntax.TemplateExpr:
		var b strings.Builder
		for _, part := range x.Parts {
			s, ok, why := c.eval(part)
			if !ok {
				return "", false, why
			}
			b.WriteString(s)
		}
		return b.String(), true, ""
	case *hclsyntax.ScopeTraversalExpr:
		ref := c.f.srcOf(x.SrcRange)
		if v, ok := c.p.refs.lookup(ref, c.f.dir, c.mod); ok {
			return v, true, ""
		}
		return "", false, "the value comes from " + ref
	}
	return "", false, "the value is computed: " + c.f.srcOf(e.Range())
}

// jsonencode edits a policy written as jsonencode({ ... Statement = ... }).
func (c *pctx) jsonencode(obj *hclsyntax.ObjectConsExpr, edits []remediate.Edit) error {
	item := objectItem(obj, "Statement")
	if item == nil {
		return todo("the policy has no Statement")
	}
	l := &hclStmts{c: c, item: item}
	switch v := item.ValueExpr.(type) {
	case *hclsyntax.TupleConsExpr:
		l.tuple, l.stmts = v, v.Exprs
	case *hclsyntax.ObjectConsExpr:
		l.stmts = []hclsyntax.Expression{v}
	default:
		return todo("Statement is not a list of object literals")
	}
	return editPolicy(l, edits, c.doc.ID(), c.removePolicy)
}

// hclStmts are the statements of a jsonencode policy: a tuple of object
// literals, or one object.
type hclStmts struct {
	c     *pctx
	item  *hclsyntax.ObjectConsItem
	tuple *hclsyntax.TupleConsExpr
	stmts []hclsyntax.Expression
}

func (l *hclStmts) count() int { return len(l.stmts) }

func (l *hclStmts) render(s *model.StatementInput) (string, error) {
	return hclStatement(s, l.c.resolve)
}

func (l *hclStmts) removeValues(i int, e *remediate.Edit) (bool, error) {
	so, ok := l.stmts[i].(*hclsyntax.ObjectConsExpr)
	if !ok {
		return false, todo("statement %d is not an object literal", i)
	}
	return l.c.removeValues(so, e)
}

func (l *hclStmts) setValues(i int, e *remediate.Edit) error {
	so, ok := l.stmts[i].(*hclsyntax.ObjectConsExpr)
	if !ok {
		return todo("statement %d is not an object literal", i)
	}
	val, err := l.c.elementValue(e, hclValue, func(k, v string) string { return "{ " + k + " = " + v + " }" })
	if err != nil {
		return todo("%s", err.Error())
	}
	f := l.c.f
	if it := objectItem(so, e.Element); it != nil {
		r := it.ValueExpr.Range()
		f.replace(r.Start.Byte, r.End.Byte, val)
		return nil
	}
	if it := objectItem(so, "Not"+e.Element); it != nil {
		f.replace(it.KeyExpr.Range().Start.Byte, it.ValueExpr.Range().End.Byte, e.Element+" = "+val)
		return nil
	}
	return todo("statement %d has no %s to narrow", i, e.Element)
}

// elementValue renders the values of a set-values edit: a list of
// resources, or an AWS principal object (obj renders {AWS = list}).
func (c *pctx) elementValue(e *remediate.Edit, render func(value) string, obj func(k, v string) string) (string, error) {
	l, err := list(e.Values, c.resolve, render)
	if err != nil || e.Element == "Resource" {
		return l, err
	}
	return obj("AWS", l), nil
}

func (l *hclStmts) commit(removed map[int]bool, added []string) error {
	f := l.c.f
	if l.tuple == nil {
		if len(added) > 0 { // one statement object: make it a list
			r := l.item.ValueExpr.Range()
			f.replace(r.Start.Byte, r.End.Byte, "["+f.srcOf(r)+", "+strings.Join(added, ", ")+"]")
		}
		return nil
	}
	for i := len(l.stmts) - 1; i >= 0; i-- {
		if removed[i] {
			removeElement(f.text, tupleRanges(l.tuple), i)
		}
	}
	if len(added) > 0 {
		insertElements(f.text, l.tuple.SrcRange, tupleRanges(l.tuple), added)
	}
	return nil
}

// valueList is the values of an object item: a tuple's elements, or the
// one value.
func valueList(e hclsyntax.Expression) (*hclsyntax.TupleConsExpr, []hclsyntax.Expression) {
	if t, ok := e.(*hclsyntax.TupleConsExpr); ok {
		return t, t.Exprs
	}
	return nil, []hclsyntax.Expression{e}
}

// removeValues removes the edit's values from the statement's Resource or
// Principal.AWS; true when nothing is left (the statement goes).
func (c *pctx) removeValues(so *hclsyntax.ObjectConsExpr, e *remediate.Edit) (bool, error) {
	holder, key := so, e.Element
	if e.Element == "Principal" {
		it := objectItem(so, "Principal")
		if it == nil {
			return false, todo("statement %d has no Principal", e.Index)
		}
		po, ok := it.ValueExpr.(*hclsyntax.ObjectConsExpr)
		if !ok {
			return false, todo("the Principal of statement %d is not an object literal", e.Index)
		}
		holder, key = po, "AWS"
	}
	it := objectItem(holder, key)
	if it == nil {
		return false, todo("statement %d has no %s", e.Index, key)
	}
	tup, vals := valueList(it.ValueExpr)
	drop, err := c.matching(len(vals), func(i int) (string, bool, string) { return c.eval(vals[i]) }, e, key)
	if err != nil || len(drop) == len(vals) {
		return err == nil, err
	}
	for i := len(drop) - 1; i >= 0; i-- {
		removeElement(c.f.text, tupleRanges(tup), drop[i])
	}
	return false, nil
}
