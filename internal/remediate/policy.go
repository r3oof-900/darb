package remediate

import (
	"fmt"
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
)

// policySide: a narrow fix adds an explicit Deny scoped to exactly this
// edge to a policy of the side (the legitimate scope of the broad grant is
// not in the input, so the grant itself is left as it is); a revoke fix
// removes the explicit grants, and denies what broad grants remain.
func (x *context) policySide(t *target, deny *model.StatementInput, why string) {
	deny.Sid, deny.Effect = x.sid, model.EffectDeny
	explicit, broad := x.grants(t)
	if x.fix.Kind == graph.FixNarrow || len(broad) > 0 {
		doc, reason := x.denyTarget()
		if doc == "" {
			x.todo("%s", reason)
			return
		}
		x.change.Edits = append(x.change.Edits, Edit{Op: OpAddStatement, Policy: doc, Statement: deny})
		x.change.Why = why
	}
	if x.fix.Kind == graph.FixRevoke {
		for _, g := range explicit {
			x.change.Edits = append(x.change.Edits, x.revoke(g, t))
		}
		x.change.Why = "remove the explicit grant (" + x.fix.Policy + ")"
		if len(broad) > 0 {
			x.change.Why += " and " + why
		}
	}
}

// grants splits the side's granting statements into explicit and broad.
func (x *context) grants(t *target) (explicit, broad []graph.Grant) {
	for _, g := range x.fix.Grants {
		s := x.statement(g)
		if s != nil && t.names(s, x.fix.Side) {
			explicit = append(explicit, g)
		} else {
			broad = append(broad, g)
		}
	}
	return explicit, broad
}

// revoke removes the target from an explicit grant: the resource values
// naming it (identity side), the principal values (resource side), or the
// statement when it is bound to the target by its encryption context.
func (x *context) revoke(g graph.Grant, t *target) Edit {
	s := x.statement(g)
	if t.context != "" {
		return Edit{Op: OpRemoveStatement, Policy: g.Policy, Index: g.Statement}
	}
	if x.fix.Side == graph.SideIdentity {
		rs, _ := s.Resources()
		return Edit{Op: OpRemoveValues, Policy: g.Policy, Index: g.Statement, Element: "Resource", Values: slices.DeleteFunc(rs, func(r string) bool { return !t.namesResource(r) })}
	}
	spec, _ := s.Principal()
	var vals []string
	for _, r := range spec.Refs() {
		if r.Value == t.principal {
			vals = append(vals, r.Value)
		}
	}
	return Edit{Op: OpRemoveValues, Policy: g.Policy, Index: g.Statement, Element: "Principal", Values: vals}
}

// denyTarget: the policy the Deny goes in. On the identity side, a policy
// of the principal that no other principal uses (an inline policy); on a
// resource or trust side, the resource's own policy as written (not a
// documented default, which has no text to edit).
func (x *context) denyTarget() (doc, reason string) {
	uses := map[string][]*model.AttachedPolicy{}
	for _, ap := range x.in.Inventory.Policies {
		uses[ap.Doc.ID()] = append(uses[ap.Doc.ID()], ap)
	}
	for _, g := range x.fix.Grants {
		aps := uses[g.Policy]
		switch {
		case x.fix.Side == graph.SideTrust:
			return g.Policy, ""
		case len(aps) == 1 && aps[0].Default == "" && !strings.HasPrefix(g.Policy, "arn:"):
			return g.Policy, ""
		case len(aps) == 1 && aps[0].Default != "":
			reason = fmt.Sprintf("%s is a documented default (%s): write the policy out with the statement added", g.Policy, aps[0].Default)
		default:
			reason = fmt.Sprintf("%s is a managed policy used by %d principals: add the statement to an inline policy of %s instead", g.Policy, len(aps), x.from())
		}
	}
	if reason == "" {
		reason = "no granting policy found for " + x.fix.Policy
	}
	return "", reason
}

func (x *context) statement(g graph.Grant) *model.Statement {
	doc := Document(x.in.Inventory, g.Policy)
	if doc == nil {
		return nil
	}
	for _, s := range doc.Statements() {
		if s.Index() == g.Statement {
			return s
		}
	}
	return nil
}

// Document finds a policy document of the inventory by ID: an attached
// (identity, boundary or resource) policy or a trust policy.
func Document(inv *model.Inventory, id string) *model.PolicyDocument {
	for _, ap := range slices.Concat(inv.Policies, inv.Boundaries) {
		if ap.Doc.ID() == id {
			return ap.Doc
		}
	}
	for _, t := range inv.Trusts {
		if t.Policy() != nil && t.Policy().ID() == id {
			return t.Policy()
		}
	}
	return nil
}
