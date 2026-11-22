package terraform

import (
	"fmt"

	"github.com/r3oof-900/darb/internal/collect/tfraw"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/managedpolicies"
	"github.com/r3oof-900/darb/internal/model"
)

// iam normalizes roles, their trust and permission policies, and boundaries.
// Supported: aws_iam_role (assume_role_policy, inline_policy,
// managed_policy_arns, permissions_boundary), aws_iam_role_policy,
// aws_iam_role_policy_attachment, aws_iam_policy_attachment, aws_iam_policy.
func (n *norm) iam(rs []*tfraw.Resource) {
	roles := newRoleIndex()
	for _, r := range rs {
		if r.Type == "aws_iam_role" && r.Mode == "managed" {
			roles.add(n, r, n.role(r))
		}
	}
	for _, r := range rs {
		switch r.Type {
		case "aws_iam_role_policy":
			if targets := n.roleTargets(r, attr(r, "role"), roles); len(targets) > 0 {
				text, ok := n.policyText(r.Root, attr(r, "policy"))
				n.attach(r, targets, n.parsePolicy(r, r.Address, model.PolicyIdentity, text, ok))
			}
		case "aws_iam_role_policy_attachment":
			if targets := n.roleTargets(r, attr(r, "role"), roles); len(targets) > 0 {
				n.attach(r, targets, n.managed(r, attr(r, "policy_arn"), model.PolicyIdentity))
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
	// Unconfigured inline_policy and managed_policy_arns are computed by the
	// provider and add nothing: "If this attribute is not configured,
	// Terraform will ignore policy attachments to this resource" (AWS provider
	// › aws_iam_role). A configured value that is not known stays unknown.
	if v, ok := r.Attrs.Get("inline_policy"); ok && unknownBlock(v) {
		n.gap(coverage.KindUnresolved, r, "inline_policy is not known statically; treated as unknown")
		n.b.AddPolicy(&model.AttachedPolicy{Target: p.ID(), Doc: n.unknownDoc(r.Address+".inline_policy", model.PolicyIdentity, &s)})
	}
	for i, ip := range r.Attrs.Blocks("inline_policy") {
		name, _ := n.str(r.Root, valueOf(ip, "name"))
		text, ok := n.policyText(r.Root, valueOf(ip, "policy"))
		id := fmt.Sprintf("%s.inline_policy[%d](%s)", r.Address, i, name)
		n.b.AddPolicy(&model.AttachedPolicy{Target: p.ID(), Doc: n.parsePolicy(r, id, model.PolicyIdentity, text, ok)})
	}
	if v, ok := r.Attrs.Get("managed_policy_arns"); ok && !v.Computed() {
		for _, item := range listItems(v) {
			n.b.AddPolicy(&model.AttachedPolicy{Target: p.ID(), Doc: n.managed(r, item, model.PolicyIdentity)})
		}
	}
	if v, ok := r.Attrs.Get("permissions_boundary"); ok && v.Kind != tfraw.KNull {
		n.b.AddBoundary(&model.AttachedPolicy{Target: p.ID(), Doc: n.managed(r, v, model.PolicyBoundary)})
	}
	return p.ID()
}

func (n *norm) policyAttachment(r *tfraw.Resource, roles *roleIndex) {
	v, ok := r.Attrs.Get("roles")
	if !ok {
		return
	}
	for _, item := range listItems(v) {
		if targets := n.roleTargets(r, item, roles); len(targets) > 0 {
			n.attach(r, targets, n.managed(r, attr(r, "policy_arn"), model.PolicyIdentity))
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
	return n.unknownDoc(policyARN, kind, &s)
}

// unknownBlock: a configured block whose content is not known (a dynamic
// block, or an unknown planned value). Blocks() would silently skip it.
func unknownBlock(v *tfraw.Value) bool {
	return (v.Kind == tfraw.KUnknownAfterApply || v.Kind == tfraw.KUnresolved) && !v.Computed()
}
