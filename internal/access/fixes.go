package access

import (
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/scoring"
)

// An edge's cut cost is the cheapest change that breaks it (SCORING.md §4).
// Edges that come from facts have one side; edges the evaluator decides get
// each side whose removal really changes the decision, checked by deciding
// again without that side's grant. A principal that can grant itself again
// makes a side useless (DESIGN.md §7.4): a "role with any permission" has no
// identity side; a principal that can rewrite a bucket policy, a key policy
// (or create a KMS grant) or a role's trust loses that resource side, and in
// its own account, where that resource policy alone grants, the identity
// side too: cut its identity grant and it writes the grant back on the
// resource. Its edge is then uncuttable and the cut moves before it.
//
// A policy side is a narrow fix when every statement that grants on it is
// broad (a wildcard that matches the target or the principal in general, or
// a decrypt grant with no encryption-context condition naming the data), and
// a revoke fix when one of them names the target and the principal
// explicitly: removing an explicit grant may break a function, so it costs
// more (SCORING.md §4.1).

// grantTarget is what a statement must name to be an explicit grant.
type grantTarget struct {
	action string // the requested action, named without a wildcard
	// Identity side: the exact resource ARN, or an ARN prefix ending in "/"
	// (a bucket's objects) under which wildcards are a narrow prefix. Both
	// empty: the Resource element does not decide (a decrypt's target is
	// the data, named by the encryption context).
	resource, prefix string
	principal        string // resource and trust side: the exact principal (ARN or service)
	sub              string // web identity trust: the exact :sub value
	context          string // CAN_DECRYPT[for J]: the bucket ARN J the context condition must name
}

// defaultFixes are the fixes of edges that come from facts, not policies;
// kind is the fix kind of the one side.
func defaultFixes(e *graph.Edge, policy, kind string) []graph.Fix {
	side := ""
	switch e.Kind {
	case graph.RunsAs:
		side = graph.SideWorkload
	case graph.CanEscalate:
		switch e.Sub {
		case "k8s-token":
			side = graph.SideWorkload
		case "rbac":
			side = graph.SideRBAC
		default:
			side = graph.SideIdentity
		}
	case graph.MapsTo:
		side = graph.SideMapping
	case graph.NodeRole:
		side = graph.SideNode
	case graph.Assumes:
		side = graph.SideTrust
	case graph.CanRead, graph.CanDecrypt, graph.CanReadPlaintext, graph.ExposedTo, graph.Protects:
		return nil
	}
	return []graph.Fix{{Side: side, Kind: kind, Policy: policy, Cost: scoring.FixCost(e.Kind, e.Sub, side, kind)}}
}

// factKind: the fix kind of a fact side. Removing a workload's identity, an
// RBAC binding or a mapping removes an explicit grant (revoke); turning off
// the token mount or requiring IMDSv2 narrows (SCORING.md §4.1). The costs
// of these sides are fixed.
func factKind(e *graph.Edge) string {
	switch {
	case e.Kind == graph.NodeRole, e.Kind == graph.CanEscalate && e.Sub == "k8s-token":
		return graph.FixNarrow
	default:
		return graph.FixRevoke
	}
}

// policyFixes: the identity side when the decision no longer grants without
// the principal's identity policies (and the principal cannot grant itself
// again: any permission, or a resource policy it can rewrite in its own
// account), the resource side when it no longer grants without the resource
// policies (and the principal cannot rewrite them).
func (b *builder) policyFixes(kind graph.Kind, req *eval.Request, set *eval.PolicySet, who *model.Principal, resource, policy string, t *grantTarget, canRewrite bool) []graph.Fix {
	var out []graph.Fix
	if who != nil && who.Kind() != model.KindIAMRoleAnyPermission && !regrants(who, req, canRewrite) && len(set.Identity) > 0 {
		without := *set
		without.Identity = nil
		if d := eval.Evaluate(req, &without); !grants(d.Verdict) {
			out = append(out, sideFix(kind, "", graph.SideIdentity, req, set.Identity, t, "", ""))
		}
	}
	if !canRewrite && len(set.Resource) > 0 {
		without := *set
		without.Resource = nil
		if d := eval.Evaluate(req, &without); !grants(d.Verdict) {
			side := graph.SideResource
			if kind == graph.Assumes {
				side = graph.SideTrust
			}
			out = append(out, sideFix(kind, "", side, req, set.Resource, t, resource, resource+" "+policy))
		}
	}
	sortFixes(out)
	return out
}

// sideFix prices one policy side from the statements that grant on it. An
// identity side names the granting policies; a resource side names the
// resource whose policy changes (label).
func sideFix(kind graph.Kind, sub, side string, req *eval.Request, docs []*model.PolicyDocument, t *grantTarget, resource, label string) graph.Fix {
	var stmts []*model.Statement
	var ids []string
	var refs []graph.Grant
	for _, d := range docs {
		if s := eval.Granting(req, []*model.PolicyDocument{d}); len(s) > 0 {
			stmts, ids = append(stmts, s...), append(ids, d.ID())
			for _, st := range s {
				refs = append(refs, graph.Grant{Policy: d.ID(), Statement: st.Index()})
			}
		}
	}
	if label == "" {
		slices.Sort(ids)
		label = strings.Join(ids, ", ")
	}
	k := fixKind(stmts, side, t)
	return graph.Fix{Side: side, Kind: k, Policy: label, Resource: resource, Cost: scoring.FixCost(kind, sub, side, k), Grants: refs}
}

// fixKind: revoke when any granting statement is explicit (breaking the
// edge must remove it), narrow when all of them are broad. With no granting
// statement found the grant cannot be shown to be broad: revoke.
func fixKind(stmts []*model.Statement, side string, t *grantTarget) string {
	if len(stmts) == 0 {
		return graph.FixRevoke
	}
	for _, s := range stmts {
		if explicit(s, side, t) {
			return graph.FixRevoke
		}
	}
	return graph.FixNarrow
}

// explicit: the statement names the action, the target and, on a resource
// or trust side, the principal, each by its exact value (a wildcard can
// never equal one), or the target by a narrow prefix (SCORING.md §4.1). An unresolved value (a Terraform placeholder)
// cannot be shown to be broad and counts as naming.
func explicit(s *model.Statement, side string, t *grantTarget) bool {
	if !namesAction(s, t.action) || t.context != "" && !bindsContext(s, t.context) {
		return false
	}
	if side == graph.SideIdentity {
		return namesResource(s, t)
	}
	return namesPrincipal(s, t)
}

func namesAction(s *model.Statement, action string) bool {
	acts, negated := s.Actions()
	if negated {
		return false
	}
	return slices.ContainsFunc(acts, func(a string) bool {
		return model.ContainsUnresolved(a) || strings.EqualFold(a, action)
	})
}

func namesResource(s *model.Statement, t *grantTarget) bool {
	if t.resource == "" && t.prefix == "" {
		return true
	}
	rs, negated := s.Resources()
	if negated {
		return false
	}
	return slices.ContainsFunc(rs, func(r string) bool {
		switch {
		case model.ContainsUnresolved(r):
			return true
		case t.prefix != "":
			return strings.HasPrefix(r, t.prefix) && len(r) > len(t.prefix)
		}
		return r == t.resource
	})
}

// namesPrincipal: an exact AWS or service principal, never "*" or an account
// (root); a web identity trust names the service account by an exact :sub.
func namesPrincipal(s *model.Statement, t *grantTarget) bool {
	if t.sub != "" {
		return slices.ContainsFunc(s.Conditions(), func(c model.Condition) bool {
			vals := c.Values()
			return strings.HasSuffix(strings.ToLower(c.Key()), ":sub") && !strings.Contains(c.Operator(), "Not") && len(vals) > 0 &&
				!slices.ContainsFunc(vals, func(v string) bool { return v != t.sub })
		})
	}
	spec, negated := s.Principal()
	if spec == nil || negated || spec.Wildcard() {
		return false
	}
	return slices.ContainsFunc(spec.Refs(), func(r model.PrincipalRef) bool {
		return (r.Type == model.PrincipalAWS || r.Type == model.PrincipalService) && (model.ContainsUnresolved(r.Value) || r.Value == t.principal)
	})
}

// bindsContext: a condition on the encryption-context key of J's service
// (model.EncryptionContextKey) whose every value names J (or, for a
// bucket, a narrow prefix of its objects).
func bindsContext(s *model.Statement, bucket string) bool {
	key := model.EncryptionContextKey(bucket)
	return slices.ContainsFunc(s.Conditions(), func(c model.Condition) bool {
		vals := c.Values()
		return strings.EqualFold(c.Key(), key) && !strings.Contains(c.Operator(), "Not") && len(vals) > 0 &&
			!slices.ContainsFunc(vals, func(v string) bool { return v != bucket && !strings.HasPrefix(v, bucket+"/") })
	})
}

// regrants: who can rewrite the resource policy in its own account, where
// that policy alone grants, so it can give itself the access back.
func regrants(who *model.Principal, req *eval.Request, canRewrite bool) bool {
	return canRewrite && req.ResourceAccount != "" && req.ResourceAccount == who.Account()
}

func sortFixes(fs []graph.Fix) {
	slices.SortFunc(fs, func(a, c graph.Fix) int {
		if a.Cost != c.Cost {
			return int(a.Cost - c.Cost)
		}
		return strings.Compare(a.Side, c.Side)
	})
}

// canDo: who's session may perform action on a resource (ALLOW or UNKNOWN:
// a fix is only counted when it surely holds).
func (b *builder) canDo(who *model.Principal, action, resource, account string, resourcePolicies []*model.PolicyDocument, required bool) bool {
	if who == nil {
		return false
	}
	req := &eval.Request{Principal: b.session(who), Action: action, Resource: resource, ResourceAccount: account, Context: b.context(who, nil)}
	return grants(eval.Evaluate(req, b.identitySet(who, resourcePolicies, required)).Verdict)
}
