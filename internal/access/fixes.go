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

// defaultFixes are the fixes of edges that come from facts, not policies.
func defaultFixes(e *graph.Edge, policy string) []graph.Fix {
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
	return []graph.Fix{{Side: side, Policy: policy, Cost: scoring.FixCost(e.Kind, e.Sub, side)}}
}

// policyFixes: the identity side when the decision no longer grants without
// the principal's identity policies (and the principal cannot grant itself
// again: any permission, or a resource policy it can rewrite in its own
// account), the resource side when it no longer grants without the resource
// policies (and the principal cannot rewrite them).
func (b *builder) policyFixes(kind graph.Kind, req *eval.Request, set *eval.PolicySet, who *model.Principal, resource, policy string, canRewrite bool) []graph.Fix {
	var out []graph.Fix
	if who != nil && who.Kind() != model.KindIAMRoleAnyPermission && !regrants(who, req, canRewrite) && len(set.Identity) > 0 {
		without := *set
		without.Identity = nil
		if d := eval.Evaluate(req, &without); !grants(d.Verdict) {
			out = append(out, graph.Fix{Side: graph.SideIdentity, Policy: policyIDs(set.Identity), Cost: scoring.FixCost(kind, "", graph.SideIdentity)})
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
			out = append(out, graph.Fix{Side: side, Policy: resource + " " + policy, Resource: resource, Cost: scoring.FixCost(kind, "", side)})
		}
	}
	sortFixes(out)
	return out
}

// regrants: who can rewrite the resource policy in its own account, where
// that policy alone grants, so it can give itself the access back.
func regrants(who *model.Principal, req *eval.Request, canRewrite bool) bool {
	return canRewrite && req.ResourceAccount != "" && req.ResourceAccount == who.Account()
}

func policyIDs(docs []*model.PolicyDocument) string {
	ids := make([]string, len(docs))
	for i, d := range docs {
		ids[i] = d.ID()
	}
	slices.Sort(ids)
	return strings.Join(ids, ", ")
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
