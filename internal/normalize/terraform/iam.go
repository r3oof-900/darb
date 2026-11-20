package terraform

import (
	"fmt"

	"github.com/r3oof-900/clapa/internal/collect/tfraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/managedpolicies"
	"github.com/r3oof-900/clapa/internal/model"
)

// iam normalizes roles, their trust and permission policies, and boundaries.
// Supported: aws_iam_role (assume_role_policy, inline_policy,
// managed_policy_arns, permissions_boundary), aws_iam_role_policy,
// aws_iam_role_policy_attachment, aws_iam_policy_attachment, aws_iam_policy.
func (n *norm) iam(rs []*tfraw.Resource) {
	roles := map[string]model.ID{} // "root|role name" and "root|address" -> role node
	for _, r := range rs {
		if r.Type == "aws_iam_role" && r.Mode == "managed" {
			id := n.role(r)
			roles[r.Root+"|"+n.nameOf(r)] = id
			roles[r.Root+"|"+r.Address] = id
		}
	}
	for _, r := range rs {
		switch r.Type {
		case "aws_iam_role_policy":
			if role, ok := n.roleRef(r, attr(r, "role"), roles); ok {
				text, ok := n.policyText(r.Root, attr(r, "policy"))
				n.b.AddPolicy(&model.AttachedPolicy{Target: role, Doc: n.parsePolicy(r, r.Address, model.PolicyIdentity, text, ok)})
			}
		case "aws_iam_role_policy_attachment":
			if role, ok := n.roleRef(r, attr(r, "role"), roles); ok {
				n.b.AddPolicy(&model.AttachedPolicy{Target: role, Doc: n.managed(r, attr(r, "policy_arn"), model.PolicyIdentity)})
			}
		case "aws_iam_policy_attachment":
			n.policyAttachment(r, roles)
		}
	}
}

func (n *norm) role(r *tfraw.Resource) model.ID {
	s := src(r)
	p := model.NewPrincipal(model.KindIAMRole, n.arnOf(r), n.account(r), &s)
	n.b.AddPrincipal(p)
	text, ok := n.policyText(r.Root, attr(r, "assume_role_policy"))
	n.b.AddTrust(model.NewTrustRelationship(p.ID(), n.parsePolicy(r, r.Address+".assume_role_policy", model.PolicyResource, text, ok)))
	for i, ip := range r.Attrs.Blocks("inline_policy") {
		name, _ := n.str(r.Root, valueOf(ip, "name"))
		text, ok := n.policyText(r.Root, valueOf(ip, "policy"))
		id := fmt.Sprintf("%s.inline_policy[%d](%s)", r.Address, i, name)
		n.b.AddPolicy(&model.AttachedPolicy{Target: p.ID(), Doc: n.parsePolicy(r, id, model.PolicyIdentity, text, ok)})
	}
	if v, ok := r.Attrs.Get("managed_policy_arns"); ok {
		for _, item := range listItems(v) {
			n.b.AddPolicy(&model.AttachedPolicy{Target: p.ID(), Doc: n.managed(r, item, model.PolicyIdentity)})
		}
	}
	if v, ok := r.Attrs.Get("permissions_boundary"); ok && v.Kind != tfraw.KNull {
		n.b.AddBoundary(&model.AttachedPolicy{Target: p.ID(), Doc: n.managed(r, v, model.PolicyBoundary)})
	}
	return p.ID()
}

// roleRef resolves a "role" attribute: a reference to a role resource, or a
// role name. A role that is not in the input is a coverage gap.
func (n *norm) roleRef(r *tfraw.Resource, v *tfraw.Value, roles map[string]model.ID) (model.ID, bool) {
	if v != nil && v.Kind == tfraw.KRef {
		if id, ok := roles[r.Root+"|"+v.Ref.Address]; ok {
			return id, true
		}
	}
	if name, ok := n.str(r.Root, v); ok {
		if id, ok := roles[r.Root+"|"+name]; ok {
			return id, true
		}
	}
	n.gap(coverage.KindUnresolved, r, "attached role is not defined in the input; this policy is not attached to any analysed role")
	return "", false
}

func (n *norm) policyAttachment(r *tfraw.Resource, roles map[string]model.ID) {
	v, ok := r.Attrs.Get("roles")
	if !ok {
		return
	}
	for _, item := range listItems(v) {
		if role, ok := n.roleRef(r, item, roles); ok {
			n.b.AddPolicy(&model.AttachedPolicy{Target: role, Doc: n.managed(r, attr(r, "policy_arn"), model.PolicyIdentity)})
		}
	}
}

func listItems(v *tfraw.Value) []*tfraw.Value {
	if v.Kind == tfraw.KList {
		return v.List
	}
	return []*tfraw.Value{v}
}

// managed resolves a managed policy ARN: a customer managed aws_iam_policy in
// the input, or an AWS managed policy from the vendored snapshot. Anything
// else is not guessed: an unknown document and a coverage gap.
func (n *norm) managed(r *tfraw.Resource, v *tfraw.Value, kind model.PolicyKind) *model.PolicyDocument {
	if v != nil && v.Kind == tfraw.KRef {
		if t := n.lookup(r.Root, v.Ref.Address); t != nil && t.Type == "aws_iam_policy" {
			text, ok := n.policyText(t.Root, attr(t, "policy"))
			return n.parsePolicy(t, n.arnOf(t), kind, text, ok)
		}
	}
	policyARN, ok := n.str(r.Root, v)
	if ok && managedpolicies.IsAWSManaged(policyARN) {
		if p, found := n.mp.Lookup(policyARN); found {
			return n.parsePolicy(r, policyARN, kind, string(p.Document), true)
		}
		n.gap(coverage.KindNotModelled, r, "AWS managed policy "+policyARN+" is not in the vendored snapshot; treated as unknown")
	}
	s := src(r)
	if !ok || !managedpolicies.IsAWSManaged(policyARN) {
		n.gap(coverage.KindUnresolved, r, "managed policy "+policyARN+" is not defined in the input; treated as unknown")
	}
	return unknownDoc(policyARN, kind, &s)
}
