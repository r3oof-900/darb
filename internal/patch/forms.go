package patch

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/remediate"
)

// heredoc edits a policy written as JSON in a heredoc. Interpolations may
// stand inside JSON strings ("${aws_s3_bucket.b.arn}/*"); anything else
// that is not JSON (a template directive, an interpolation between values)
// cannot be edited as JSON.
func (c *pctx) heredoc(e *hclsyntax.TemplateExpr, edits []remediate.Edit) error {
	r := e.SrcRange
	raw := string(c.f.src[r.Start.Byte:r.End.Byte])
	first := strings.IndexByte(raw, '\n')
	last := strings.LastIndexByte(strings.TrimRight(raw, " \t\r\n"), '\n')
	if first < 0 || last <= first || strings.Contains(raw, "%{") {
		return todo("the heredoc of %s is not plain JSON", c.doc.ID())
	}
	l := &jsonStmts{c: c, base: r.Start.Byte + first + 1, body: raw[first+1 : last+1]}
	root, err := parseJSON([]byte(l.body))
	if err != nil || root.kind != 'o' {
		return todo("the heredoc of %s is not a JSON object: %v", c.doc.ID(), err)
	}
	if l.stmt = root.member("Statement"); l.stmt == nil || l.stmt.kind != 'a' && l.stmt.kind != 'o' {
		return todo("the policy has no Statement list")
	}
	l.items = l.stmt.items
	if l.stmt.kind == 'o' {
		l.items = []*jnode{l.stmt}
	}
	return editPolicy(l, edits, c.doc.ID(), c.removePolicy)
}

// jsonStmts are the statements of a JSON heredoc policy; offsets are into
// the heredoc body, which starts at base in the file.
type jsonStmts struct {
	c     *pctx
	base  int
	body  string
	stmt  *jnode
	items []*jnode
}

func (l *jsonStmts) at(n *jnode) hcl.Range {
	return hcl.Range{Start: hcl.Pos{Byte: l.base + n.start}, End: hcl.Pos{Byte: l.base + n.end}}
}

func (l *jsonStmts) ranges(ns []*jnode) []hcl.Range {
	out := make([]hcl.Range, len(ns))
	for i, n := range ns {
		out[i] = l.at(n)
	}
	return out
}

func (l *jsonStmts) count() int { return len(l.items) }

func (l *jsonStmts) render(s *model.StatementInput) (string, error) {
	return statementJSON(s, l.c.resolve)
}

func (l *jsonStmts) removeValues(i int, e *remediate.Edit) (bool, error) {
	holder, key := l.items[i], e.Element
	if key == "Principal" {
		if holder = holder.member("Principal"); holder == nil || holder.kind != 'o' {
			return false, todo("the Principal of statement %d is not an object", i)
		}
		key = "AWS"
	}
	v := holder.member(key)
	if v == nil {
		return false, todo("statement %d has no %s", i, key)
	}
	vals := []*jnode{v}
	if v.kind == 'a' {
		vals = v.items
	}
	drop, err := l.c.matching(len(vals), func(j int) (string, bool, string) {
		s, ok := l.c.interpolate(vals[j].str)
		if vals[j].kind != 's' || !ok {
			return "", false, "the value is not known in the input"
		}
		return s, true, ""
	}, e, key)
	if err != nil || len(drop) == len(vals) {
		return err == nil, err
	}
	for j := len(drop) - 1; j >= 0; j-- {
		removeElement(l.c.f.text, l.ranges(vals), drop[j])
	}
	return false, nil
}

func (l *jsonStmts) commit(removed map[int]bool, added []string) error {
	f := l.c.f
	if l.stmt.kind == 'o' {
		if len(added) > 0 {
			f.replace(l.base+l.stmt.start, l.base+l.stmt.end, "["+l.body[l.stmt.start:l.stmt.end]+", "+strings.Join(added, ", ")+"]")
		}
		return nil
	}
	for i := len(l.items) - 1; i >= 0; i-- {
		if removed[i] {
			removeElement(f.text, l.ranges(l.items), i)
		}
	}
	if len(added) > 0 {
		insertElements(f.text, l.at(l.stmt), l.ranges(l.items), added)
	}
	return nil
}

// interpolate resolves the ${...} references of a heredoc string.
func (c *pctx) interpolate(s string) (string, bool) {
	var b strings.Builder
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			b.WriteString(s)
			return b.String(), true
		}
		if i > 0 && s[i-1] == '$' { // $${ is a literal ${
			b.WriteString(s[:i+2])
			s = s[i+2:]
			continue
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			return "", false
		}
		v, ok := c.p.refs.lookup(strings.TrimSpace(s[i+2:i+j]), c.f.dir, c.mod)
		if !ok {
			return "", false
		}
		b.WriteString(s[:i] + v)
		s = s[i+j+1:]
	}
}

// dataDocument edits a data "aws_iam_policy_document" of the same
// directory. It must be used by this policy only, and its statements must
// be plain blocks (no dynamic blocks, no source or override documents).
func (c *pctx) dataDocument(name string, edits []remediate.Edit) error {
	df, db, err := c.findData(name)
	if err != nil {
		return err
	}
	l := &dataStmts{c: &pctx{p: c.p, f: df, mod: c.mod, doc: c.doc}, block: db, step: "  "}
	for _, b := range db.Body.Blocks {
		switch b.Type {
		case "statement":
			l.stmts = append(l.stmts, b)
		case "dynamic":
			return todo("data.aws_iam_policy_document.%s has dynamic blocks", name)
		}
	}
	for _, a := range []string{"source_policy_documents", "override_policy_documents", "source_json", "override_json"} {
		if db.Body.Attributes[a] != nil {
			return todo("data.aws_iam_policy_document.%s merges %s", name, a)
		}
	}
	l.indent = df.indentAt(db.TypeRange.Start.Byte) + l.step
	if len(l.stmts) > 0 {
		l.indent = df.indentAt(l.stmts[0].TypeRange.Start.Byte)
	}
	return editPolicy(l, edits, c.doc.ID(), func() error {
		return todo("no statement of data.aws_iam_policy_document.%s would remain: change %s by hand", name, c.doc.ID())
	})
}

// findData finds the data source in the directory; it must be used once.
func (c *pctx) findData(name string) (*tfFile, *hclsyntax.Block, error) {
	files, err := c.p.src.List(c.f.dir)
	if err != nil {
		return nil, nil, err
	}
	var df *tfFile
	var db *hclsyntax.Block
	uses := 0
	for _, file := range files {
		f, err := c.p.tf(file)
		if err != nil {
			continue
		}
		uses += strings.Count(string(f.src), "data.aws_iam_policy_document."+name+".")
		if b := f.block("data", "aws_iam_policy_document", name); b != nil {
			df, db = f, b
		}
	}
	switch {
	case db == nil:
		return nil, nil, todo("data.aws_iam_policy_document.%s is not in %s", name, c.f.dir)
	case uses > 1:
		return nil, nil, todo("data.aws_iam_policy_document.%s is used by %d policies; a change there changes them all", name, uses)
	}
	return df, db, nil
}

// dataStmts are the statement blocks of a policy document data source.
type dataStmts struct {
	c            *pctx
	block        *hclsyntax.Block
	stmts        []*hclsyntax.Block
	indent, step string
}

func (l *dataStmts) count() int { return len(l.stmts) }

func (l *dataStmts) render(s *model.StatementInput) (string, error) {
	return dataStatement(s, l.c.resolve, l.indent, l.step, l.c.f.newline())
}

// removeValues removes values from a statement block's resources (or the
// identifiers of its AWS principals); true when none is left.
func (l *dataStmts) removeValues(i int, e *remediate.Edit) (bool, error) {
	total, dropped := 0, 0
	for _, a := range l.lists(l.stmts[i], e.Element) {
		tup, ok := a.Expr.(*hclsyntax.TupleConsExpr)
		if !ok {
			return false, todo("%s of statement %d is not a list literal", a.Name, i)
		}
		drop, err := l.c.drops(len(tup.Exprs), func(j int) (string, bool, string) { return l.c.eval(tup.Exprs[j]) }, e, a.Name)
		if err != nil {
			return false, err
		}
		total, dropped = total+len(tup.Exprs), dropped+len(drop)
		if len(drop) < len(tup.Exprs) {
			for j := len(drop) - 1; j >= 0; j-- {
				removeElement(l.c.f.text, tupleRanges(tup), drop[j])
			}
		}
	}
	if dropped == 0 {
		return false, fmt.Errorf("patch: %s statement %d: none of %v found", l.c.doc.ID(), i, e.Values)
	}
	return dropped == total, nil
}

// lists are the attributes holding a statement's resources, or its AWS
// principals' identifiers.
func (l *dataStmts) lists(b *hclsyntax.Block, element string) []*hclsyntax.Attribute {
	if element == "Resource" {
		if a := b.Body.Attributes["resources"]; a != nil {
			return []*hclsyntax.Attribute{a}
		}
		return nil
	}
	var out []*hclsyntax.Attribute
	for _, pb := range b.Body.Blocks {
		t, ids := pb.Body.Attributes["type"], pb.Body.Attributes["identifiers"]
		if pb.Type != "principals" || t == nil || ids == nil {
			continue
		}
		if s, ok, _ := l.c.eval(t.Expr); ok && s == string(model.PrincipalAWS) {
			out = append(out, ids)
		}
	}
	return out
}

func (l *dataStmts) commit(removed map[int]bool, added []string) error {
	f := l.c.f
	for i, b := range l.stmts {
		if removed[i] {
			f.deleteLines(b.TypeRange.Start.Byte, b.CloseBraceRange.End.Byte-1)
		}
	}
	if len(added) == 0 {
		return nil
	}
	if !f.onlySpaceBefore(l.block.CloseBraceRange.Start.Byte) {
		return todo("the data source closes on a line with other text")
	}
	at := f.lineStart(l.block.CloseBraceRange.Start.Byte)
	f.replace(at, at, strings.Join(added, f.newline())+f.newline())
	return nil
}
