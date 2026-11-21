package patch

import (
	"fmt"
	"path"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// removePolicy: every statement goes. An inline policy resource is removed
// whole; any other policy (a trust, a key or bucket policy) cannot be empty.
func (c *pctx) removePolicy() error {
	src := c.doc.Source()
	_, local := moduleOf(src.Address())
	typ, name, _, _ := resourceAddr(local)
	if typ != "aws_iam_role_policy" {
		return todo("no statement of %s would remain; a %s cannot be empty: change it by hand", c.doc.ID(), typ)
	}
	b := c.f.block("resource", typ, name)
	start, end := b.TypeRange.Start.Byte, b.CloseBraceRange.End.Byte
	if c.f.onlySpaceBefore(start) {
		c.f.deleteLines(start, end-1)
		// and one blank line before it, so two do not remain
		if ls := c.f.lineStart(start); ls >= 2 && c.f.src[ls-1] == '\n' && strings.TrimSpace(string(c.f.src[c.f.lineStart(ls-1):ls])) == "" {
			c.f.splices[len(c.f.splices)-1].start = c.f.lineStart(ls - 1)
		}
		return nil
	}
	c.f.replace(start, end, "")
	return nil
}

func tupleRanges(t *hclsyntax.TupleConsExpr) []hcl.Range {
	out := make([]hcl.Range, len(t.Exprs))
	for i, e := range t.Exprs {
		out[i] = e.Range()
	}
	return out
}

// removeElement deletes element i of a list (HCL tuple or JSON array) with
// its separator: up to the next element, or from the previous one for the
// last (so no comma dangles, which JSON forbids).
func removeElement(t *text, elems []hcl.Range, i int) {
	switch {
	case i+1 < len(elems):
		t.replace(elems[i].Start.Byte, elems[i+1].Start.Byte, "")
	case i > 0:
		t.replace(elems[i-1].End.Byte, elems[i].End.Byte, "")
	default:
		t.replace(elems[i].Start.Byte, elems[i].End.Byte, "")
	}
}

// insertElements appends items to a list whose range is r: each on its own
// line with the last element's indentation when the list spans lines,
// otherwise after ", ". A trailing comma is kept.
func insertElements(t *text, r hcl.Range, elems []hcl.Range, items []string) {
	if len(elems) == 0 {
		t.replace(r.Start.Byte+1, r.Start.Byte+1, strings.Join(items, ", "))
		return
	}
	last := elems[len(elems)-1]
	closing := r.End.Byte - 1
	after := strings.TrimSpace(string(t.src[last.End.Byte:closing]))
	trailing := strings.HasPrefix(after, ",")
	multiline := strings.Contains(string(t.src[last.End.Byte:closing]), "\n")
	pos := last.End.Byte
	if trailing {
		pos = last.End.Byte + strings.Index(string(t.src[last.End.Byte:closing]), ",") + 1
	}
	var b strings.Builder
	if !trailing {
		b.WriteString(",")
	}
	for i, it := range items {
		if multiline {
			b.WriteString(t.newline() + t.indentAt(last.Start.Byte) + it)
		} else {
			b.WriteString(" " + it)
		}
		if i < len(items)-1 || trailing {
			b.WriteString(",")
		}
	}
	t.replace(pos, pos, b.String())
}

// inputHint: when a value comes from var.X inside a module, the module call
// that sets it (the place a revoke would change; the input does not say to
// what).
func (p *patcher) inputHint(f *tfFile, mod, why string) string {
	v, ok := strings.CutPrefix(why, "the value comes from var.")
	if !ok || mod == "" {
		return "change it where the value is set; the input does not say to what"
	}
	v = strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '[' })[0]
	name := mod[strings.LastIndex(mod, ".")+1:]
	for dir := path.Dir(f.dir); ; dir = path.Dir(dir) {
		if file, mf, a := p.moduleInput(dir, name, v); a != nil {
			return fmt.Sprintf("var.%s is the input %q of module %q at %s:%d (%s); revoking means changing that input to what the module's principals need, or removing them: the input does not say which",
				v, v, name, file, a.SrcRange.Start.Line, strings.TrimSpace(mf.srcOf(a.SrcRange)))
		}
		if dir == "." || dir == "/" || dir == "" {
			break
		}
	}
	return "var." + v + " is set by the caller of " + mod + "; change it there"
}

// moduleInput finds, among the .tf files of dir, the module call name and
// its input attribute.
func (p *patcher) moduleInput(dir, name, input string) (string, *tfFile, *hclsyntax.Attribute) {
	files, _ := p.src.List(dir)
	for _, file := range files {
		mf, err := p.tf(file)
		if err != nil {
			continue
		}
		for _, b := range mf.body.Blocks {
			if b.Type == "module" && len(b.Labels) == 1 && b.Labels[0] == name && b.Body.Attributes[input] != nil {
				return file, mf, b.Body.Attributes[input]
			}
		}
	}
	return "", nil, nil
}
