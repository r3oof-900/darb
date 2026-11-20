package access

import (
	"maps"
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/eval/condition"
	"github.com/r3oof-900/clapa/internal/eval/match"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
)

// identities adds the IAM edges between principals (DESIGN.md §7.2):
// ASSUMES[sts] (role chaining), CAN_ESCALATE[iam:passrole:<service>]
// (iam:PassRole into compute that runs as the passed role),
// CAN_ESCALATE[iam:update-trust] (rewriting a role's trust to assume it)
// and CAN_ESCALATE[iam:modify-policy] (CreatePolicyVersion,
// AttachRolePolicy, PutRolePolicy) into "role with any permission" — a
// synthetic principal whose identity policy allows everything but which is
// still limited by the role's permissions boundary, resource policies and
// key policies. Sources include those synthetic principals, until no new
// one appears.
func (b *builder) identities() {
	queue := append([]*model.Principal(nil), b.roles...)
	for len(queue) > 0 {
		src := queue[0]
		queue = queue[1:]
		for _, dst := range b.roles {
			trust, ok := b.trusts[dst.ID()]
			if !ok {
				continue
			}
			act := eval.Allow // a role acts as itself
			if src.Identity() != dst.Identity() {
				act = either(b.chain(src, dst, trust), b.updateTrust(src, dst))
				b.passRole(src, dst, trust)
			}
			if rewritten, ok := b.modifyPolicy(src, dst, act); ok {
				queue = append(queue, rewritten)
			}
		}
	}
}

func (b *builder) chain(src, dst *model.Principal, trust *model.PolicyDocument) eval.Verdict {
	req := &eval.Request{
		Principal: b.session(src), Action: "sts:AssumeRole", Resource: dst.Identity(),
		ResourceAccount: dst.Account(), Context: b.context(src, nil),
	}
	set := b.identitySet(src, []*model.PolicyDocument{trust}, true)
	d := eval.Evaluate(req, set)
	if grants(d.Verdict) {
		rewrite := b.canDo(src, "iam:UpdateAssumeRolePolicy", dst.Identity(), dst.Account(), nil, false)
		b.edge(src.ID(), dst.ID(), graph.Assumes, "sts", &d, func(e *graph.Edge) {
			t := &grantTarget{action: "sts:AssumeRole", resource: dst.Identity(), principal: src.Identity()}
			e.Fixes = nonNil(b.policyFixes(graph.Assumes, req, set, src, dst.Identity(), "trust policy", t, rewrite))
		})
	}
	return d.Verdict
}

// ask evaluates one action of src's session on a resource of src's account.
func (b *builder) ask(src *model.Principal, action, resource string, present map[string][]string) eval.Decision {
	return eval.Evaluate(b.request(src, action, resource, present), b.identitySet(src, nil, false))
}

func (b *builder) request(src *model.Principal, action, resource string, present map[string][]string) *eval.Request {
	return &eval.Request{
		Principal: b.session(src), Action: action, Resource: resource, ResourceAccount: src.Account(),
		Context: b.context(src, present),
	}
}

// identityKind: the fix kind of src's identity grant of action on resource
// (SCORING.md §4.1): revoke when a granting statement names both exactly.
func (b *builder) identityKind(src *model.Principal, action, resource string, present map[string][]string) string {
	req := b.request(src, action, resource, present)
	return fixKind(eval.Granting(req, b.identitySet(src, nil, false).Identity), graph.SideIdentity, &grantTarget{action: action, resource: resource})
}

// updateTrust: iam:UpdateAssumeRolePolicy on dst lets src name itself in
// dst's trust and assume it (in another account src's identity policy must
// also allow sts:AssumeRole on dst).
func (b *builder) updateTrust(src, dst *model.Principal) eval.Verdict {
	update := b.ask(src, "iam:UpdateAssumeRolePolicy", dst.Identity(), nil)
	verdict := update.Verdict
	if !sameAccount(src, dst) {
		verdict = both(verdict, b.ask(src, "sts:AssumeRole", dst.Identity(), nil).Verdict)
	}
	if grants(verdict) {
		kind := b.identityKind(src, "iam:UpdateAssumeRolePolicy", dst.Identity(), nil)
		b.edge(src.ID(), dst.ID(), graph.CanEscalate, "iam:update-trust", &eval.Decision{Verdict: verdict}, func(e *graph.Edge) {
			e.Evidence = evidence(&update)
			e.Fixes = nonNil(b.factFixes(e, kind))
		})
	}
	return verdict
}

func sameAccount(a, b *model.Principal) bool { return a.Account() == b.Account() && a.Account() != "" }

// modifyPolicy: CreatePolicyVersion on a customer managed policy attached to
// dst, or AttachRolePolicy / PutRolePolicy on dst, give dst any permission;
// src uses it when it is or can become dst (act). It returns the synthetic
// principal when the edge is new.
func (b *builder) modifyPolicy(src, dst *model.Principal, act eval.Verdict) (*model.Principal, bool) {
	if !grants(act) || src.Kind() == model.KindIAMRoleAnyPermission && src.Identity() == dst.Identity() {
		return nil, false
	}
	modify := eval.ImplicitDeny
	var why []string
	kind := graph.FixNarrow
	try := func(action, resource string) {
		d := b.ask(src, action, resource, nil)
		if v := either(modify, d.Verdict); v != modify {
			modify, why = v, append(evidence(&d), action+" on "+resource)
		}
		if grants(d.Verdict) && b.identityKind(src, action, resource, nil) == graph.FixRevoke {
			kind = graph.FixRevoke // every granting way must go: one explicit grant makes it a revoke
		}
	}
	try("iam:AttachRolePolicy", dst.Identity())
	try("iam:PutRolePolicy", dst.Identity())
	for _, doc := range b.policies[dst.ID()] {
		if customerManaged(doc.ID()) {
			try("iam:CreatePolicyVersion", doc.ID())
		}
	}
	verdict := both(modify, act)
	if !grants(verdict) {
		return nil, false
	}
	target, isNew := b.anyPermission(dst)
	b.edge(src.ID(), target.ID(), graph.CanEscalate, "iam:modify-policy", &eval.Decision{Verdict: verdict}, func(e *graph.Edge) {
		e.Evidence = why
		e.Fixes = nonNil(b.factFixes(e, kind))
	})
	return target, isNew
}

// customerManaged: a managed policy ARN of an account (AWS managed policies,
// arn:aws:iam::aws:policy/..., cannot be versioned by customers).
func customerManaged(id string) bool {
	account, name, ok := policyParts(id)
	return ok && account != "aws" && name != ""
}

func policyParts(arn string) (account, name string, ok bool) {
	_, rest, found := strings.Cut(arn, ":iam::")
	if !found {
		return "", "", false
	}
	account, name, ok = strings.Cut(rest, ":policy/")
	return account, name, ok
}

// anyPermission returns the synthetic "dst with any permission" principal:
// an identity policy that allows everything, dst's permissions boundary.
func (b *builder) anyPermission(dst *model.Principal) (*model.Principal, bool) {
	id := model.NewID(model.KindIAMRoleAnyPermission, dst.Identity())
	if p, ok := b.rewritten[id]; ok {
		return p, false
	}
	p := model.NewPrincipal(model.KindIAMRoleAnyPermission, dst.Identity(), dst.Account(), dst.Source())
	b.rewritten[id] = p
	b.order = append(b.order, p)
	b.g.Node(p.ID(), p.Kind(), dst.Identity()+" (any permission)")
	b.policies[p.ID()] = []*model.PolicyDocument{allowAll()}
	if boundary, ok := b.boundaries[dst.ID()]; ok {
		b.boundaries[p.ID()] = boundary
	}
	return p, true
}

func allowAll() *model.PolicyDocument {
	d, _ := model.NewPolicyDocument(&model.PolicyInput{ // a fixed, valid document
		ID: "clapa:any-permission", Kind: model.PolicyIdentity, Version: model.Version2012,
		Statements: []*model.StatementInput{{Effect: model.EffectAllow, Action: []string{"*"}, Resource: []string{"*"}}},
	})
	return d
}

// computeService describes compute that runs as a passed role.
type computeService struct {
	principal string   // service principal the role's trust must allow
	create    []string // all needed to create the compute
	run       []string // any one runs it; empty: creating runs it
	resource  string   // resource type in the ARN
}

// passRoleServices: compute a role can be passed to (IAM User Guide ›
// "Granting a user permissions to pass a role to an AWS service").
func passRoleServices() map[string]computeService {
	return map[string]computeService{
		"lambda":         {"lambda.amazonaws.com", []string{"lambda:CreateFunction"}, []string{"lambda:InvokeFunction", "lambda:CreateEventSourceMapping", "lambda:CreateFunctionUrlConfig"}, "function"},
		"ec2":            {"ec2.amazonaws.com", []string{"ec2:RunInstances"}, nil, "instance"},
		"ecs-tasks":      {"ecs-tasks.amazonaws.com", []string{"ecs:RegisterTaskDefinition"}, []string{"ecs:RunTask", "ecs:StartTask", "ecs:CreateService"}, "task-definition"},
		"cloudformation": {"cloudformation.amazonaws.com", []string{"cloudformation:CreateStack"}, nil, "stack"},
		"glue":           {"glue.amazonaws.com", []string{"glue:CreateJob"}, []string{"glue:StartJobRun"}, "job"},
		"codebuild":      {"codebuild.amazonaws.com", []string{"codebuild:CreateProject"}, []string{"codebuild:StartBuild"}, "project"},
		"sagemaker":      {"sagemaker.amazonaws.com", []string{"sagemaker:CreateNotebookInstance"}, nil, "notebook-instance"},
	}
}

// passRole: for each compute service dst trusts, iam:PassRole on dst (to
// that service) and the create actions make compute that runs as dst; an
// execution primitive runs it. Without one the escalation is reported with
// medium confidence: creating alone runs nothing until something does
// (DESIGN.md §13.2, scenario 7).
func (b *builder) passRole(src, dst *model.Principal, trust *model.PolicyDocument) {
	for _, name := range slices.Sorted(maps.Keys(passRoleServices())) {
		svc := passRoleServices()[name]
		service := &eval.Request{
			Principal: match.RequestPrincipal{Kind: match.KindService, ARN: svc.principal}, Action: "sts:AssumeRole",
			Resource: dst.Identity(), ResourceAccount: dst.Account(),
			Context: condition.NewContext(&condition.Input{Default: condition.StateUnknown}),
		}
		trusted := eval.Evaluate(service, TrustPolicySet(trust))
		if !grants(trusted.Verdict) {
			continue
		}
		target := "arn:" + b.opts.Partition + ":" + serviceOf(name) + ":" + model.UnresolvedPlaceholder("region") + ":" + src.Account() +
			":" + svc.resource + "/" + model.UnresolvedPlaceholder("name")
		pass := b.ask(src, "iam:PassRole", dst.Identity(), map[string][]string{"iam:PassedToService": {svc.principal}})
		verdict := both(pass.Verdict, trusted.Verdict)
		why := append(evidence(&pass), evidence(&trusted)...)
		for _, action := range svc.create {
			d := b.ask(src, action, target, nil)
			verdict, why = both(verdict, d.Verdict), append(why, evidence(&d)...)
		}
		if !grants(verdict) {
			continue
		}
		run := eval.Allow
		if len(svc.run) > 0 {
			run = eval.ImplicitDeny
			for _, action := range svc.run {
				run = either(run, b.ask(src, action, target, nil).Verdict)
			}
		}
		kind := b.identityKind(src, "iam:PassRole", dst.Identity(), map[string][]string{"iam:PassedToService": {svc.principal}})
		trustFix := sideFix(graph.Assumes, "", graph.SideTrust, service, []*model.PolicyDocument{trust},
			&grantTarget{action: "sts:AssumeRole", principal: svc.principal}, dst.Identity(), dst.Identity()+" trust policy")
		b.edge(src.ID(), dst.ID(), graph.CanEscalate, "iam:passrole:"+name, &eval.Decision{Verdict: verdict}, func(e *graph.Edge) {
			e.Evidence = why
			e.Fixes = append(b.factFixes(e, kind), trustFix)
			sortFixes(e.Fixes)
			switch run {
			case eval.Allow:
			case eval.Unknown:
				e.Confidence = graph.Low
			case eval.Deny, eval.ImplicitDeny:
				e.Confidence = min(e.Confidence, graph.Medium)
				e.Evidence = append(e.Evidence, "no execution primitive for "+name)
			}
		})
	}
}

// serviceOf is the ARN service segment of a passRoleServices key.
func serviceOf(name string) string {
	if name == "ecs-tasks" {
		return "ecs"
	}
	return name
}

// either is the verdict of alternatives of which one suffices.
func either(a, b eval.Verdict) eval.Verdict {
	switch {
	case a == eval.Allow || b == eval.Allow:
		return eval.Allow
	case a == eval.Unknown || b == eval.Unknown:
		return eval.Unknown
	case a == eval.Deny && b == eval.Deny:
		return eval.Deny
	}
	return eval.ImplicitDeny
}
