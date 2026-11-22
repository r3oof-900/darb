package patch

import (
	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/r3oof-900/darb/internal/remediate"
)

// detachPolicy removes an AWS managed policy's attachment to a role
// (SCORING.md §4.1): the ARN from the role's managed_policy_arns, or the
// aws_iam_role_policy_attachment resource that attaches it. The AWS
// managed document itself is never edited; its replacement is the owner's
// (the change's TODO).
func (p *patcher) detachPolicy(e *remediate.Edit) error {
	role := e.Principal
	src := role.Source()
	mod, local := moduleOf(src.Address())
	typ, name, indexed, ok := resourceAddr(local)
	if !ok || indexed || typ != "aws_iam_role" || !strings.HasSuffix(src.File(), ".tf") {
		return todo("%s is not an aws_iam_role of this input: detach %s from it by hand", role.Identity(), e.Policy)
	}
	f, err := p.tf(src.File())
	if err != nil {
		return err
	}
	if b := f.block("resource", typ, name); b != nil {
		if a := b.Body.Attributes["managed_policy_arns"]; a != nil {
			if tup, isTuple := a.Expr.(*hclsyntax.TupleConsExpr); isTuple {
				c := &pctx{p: p, f: f, mod: mod}
				for i, x := range tup.Exprs {
					if v, ok, _ := c.eval(x); ok && v == e.Policy {
						removeElement(f.text, tupleRanges(tup), i)
						return nil
					}
				}
			}
		}
	}
	return p.detachAttachment(dirOf(src.File()), mod, name, role.Identity(), e.Policy)
}

// detachAttachment deletes the aws_iam_role_policy_attachment of policy to
// the role aws_iam_role.<name>.
func (p *patcher) detachAttachment(dir, mod, name, roleARN, policy string) error {
	files, _ := p.src.List(dir)
	for _, file := range files {
		f, err := p.tf(file)
		if err != nil {
			continue
		}
		c := &pctx{p: p, f: f, mod: mod}
		for _, b := range f.body.Blocks {
			if c.attaches(b, name, roleARN, policy) {
				start, end := b.TypeRange.Start.Byte, b.CloseBraceRange.End.Byte
				if f.onlySpaceBefore(start) {
					f.deleteLines(start, end-1)
				} else {
					f.replace(start, end, "")
				}
				return nil
			}
		}
	}
	return todo("no managed_policy_arns entry or aws_iam_role_policy_attachment attaches %s to %s: detach it by hand", policy, roleARN)
}

// attaches: b is an aws_iam_role_policy_attachment of policy to the role
// (by name, ARN or a reference to aws_iam_role.<name>).
func (c *pctx) attaches(b *hclsyntax.Block, name, roleARN, policy string) bool {
	if b.Type != "resource" || len(b.Labels) != 2 || b.Labels[0] != "aws_iam_role_policy_attachment" {
		return false
	}
	pa, ra := b.Body.Attributes["policy_arn"], b.Body.Attributes["role"]
	if pa == nil || ra == nil {
		return false
	}
	if v, ok, _ := c.eval(pa.Expr); !ok || v != policy {
		return false
	}
	if strings.HasPrefix(strings.TrimSpace(c.f.srcOf(ra.Expr.Range())), "aws_iam_role."+name+".") {
		return true
	}
	r, ok, _ := c.eval(ra.Expr)
	return ok && (r == roleARN || r == roleARN[strings.LastIndex(roleARN, "/")+1:])
}
