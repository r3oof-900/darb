package access

import (
	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/eval/condition"
	"github.com/r3oof-900/clapa/internal/eval/match"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
)

// identities adds ASSUMES[sts] (role chaining) and CAN_ESCALATE[iam]
// (iam:PassRole into a Lambda function that runs as the passed role).
func (b *builder) identities() {
	for _, src := range b.roles {
		for _, dst := range b.roles {
			if src.ID() == dst.ID() {
				continue
			}
			trust, ok := b.trusts[dst.ID()]
			if !ok {
				continue
			}
			b.chain(src, dst, trust)
			b.passRole(src, dst, trust)
		}
	}
}

func (b *builder) chain(src, dst *model.Principal, trust *model.PolicyDocument) {
	req := &eval.Request{
		Principal: b.session(src), Action: "sts:AssumeRole", Resource: dst.Identity(),
		ResourceAccount: dst.Account(), Context: b.context(src, nil),
	}
	if d := eval.Evaluate(req, b.identitySet(src, []*model.PolicyDocument{trust}, true)); grants(d.Verdict) {
		b.edge(src.ID(), dst.ID(), graph.Assumes, "sts", &d, nil)
	}
}

// passRole: iam:PassRole on dst (to Lambda) and lambda:CreateFunction make a
// function that runs as dst; an execution primitive (InvokeFunction,
// CreateEventSourceMapping, CreateFunctionUrlConfig) runs it. Without one the
// escalation is reported with medium confidence: creating alone runs nothing
// until something invokes the function (DESIGN.md §13.2, scenario 7).
func (b *builder) passRole(src, dst *model.Principal, trust *model.PolicyDocument) {
	lambda := &eval.Request{
		Principal: match.RequestPrincipal{Kind: match.KindService, ARN: "lambda.amazonaws.com"}, Action: "sts:AssumeRole",
		Resource: dst.Identity(), ResourceAccount: dst.Account(),
		Context: condition.NewContext(&condition.Input{Default: condition.StateUnknown}),
	}
	trusted := eval.Evaluate(lambda, TrustPolicySet(trust))
	if !grants(trusted.Verdict) {
		return
	}
	ask := func(action, resource string, present map[string][]string) eval.Decision {
		req := &eval.Request{
			Principal: b.session(src), Action: action, Resource: resource, ResourceAccount: src.Account(),
			Context: b.context(src, present),
		}
		return eval.Evaluate(req, b.identitySet(src, nil, false))
	}
	fn := "arn:" + b.opts.Partition + ":lambda:" + model.UnresolvedPlaceholder("region") + ":" + src.Account() +
		":function:" + model.UnresolvedPlaceholder("function-name")
	pass := ask("iam:PassRole", dst.Identity(), map[string][]string{"iam:PassedToService": {"lambda.amazonaws.com"}})
	create := ask("lambda:CreateFunction", fn, nil)
	verdict := both(both(pass.Verdict, create.Verdict), trusted.Verdict)
	if !grants(verdict) {
		return
	}
	run := eval.ImplicitDeny
	for _, action := range []string{"lambda:InvokeFunction", "lambda:CreateEventSourceMapping", "lambda:CreateFunctionUrlConfig"} {
		run = either(run, ask(action, fn, nil).Verdict)
	}
	b.edge(src.ID(), dst.ID(), graph.CanEscalate, "iam", &eval.Decision{Verdict: verdict}, func(e *graph.Edge) {
		e.Evidence = append(append(evidence(&pass), evidence(&create)...), evidence(&trusted)...)
		switch run {
		case eval.Allow:
		case eval.Unknown:
			e.Confidence = graph.Low
		case eval.Deny, eval.ImplicitDeny:
			e.Confidence = min(e.Confidence, graph.Medium)
			e.Evidence = append(e.Evidence, "no execution primitive (InvokeFunction, CreateEventSourceMapping, CreateFunctionUrlConfig)")
		}
	})
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
