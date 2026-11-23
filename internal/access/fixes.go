package access

import (
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/scoring"
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
// RBAC binding or a mapping removes an explicit grant (revoke), and so does
// turning off the token mount: on a path the token always carries the RBAC
// rights the path uses, granted on purpose (Phase 6 review; without a
// binding it is on no path, and turning it off is hardening). Requiring
// IMDSv2 narrows (SCORING.md §4.1). The costs of these sides are fixed.
func factKind(e *graph.Edge) string {
	if e.Kind == graph.NodeRole {
		return graph.FixNarrow
	}
	return graph.FixRevoke
}

// policyFixes: the identity side when the decision no longer grants without
// the principal's identity policies (and the principal cannot grant itself
// again: any permission, or a resource policy it can rewrite in its own
// account), the resource side when it no longer grants without the resource
// policies (and the principal cannot rewrite them).
func (b *builder) policyFixes(kind graph.Kind, req *eval.Request, set *eval.PolicySet, who *model.Principal, resource, policy string, t *grantTarget, rw *rewriter) []graph.Fix {
	var out []graph.Fix
	if who != nil && who.Kind() != model.KindIAMRoleAnyPermission && len(set.Identity) > 0 {
		without := *set
		without.Identity = nil
		if d := eval.Evaluate(req, &without); !grants(d.Verdict) {
			fx := sideFix(kind, "", graph.SideIdentity, req, set.Identity, t, "", "", who.Identity())
			out = appendSide(out, &fx, rw.guardsIdentity(&fx))
		}
	}
	if len(set.Resource) > 0 {
		without := *set
		without.Resource = nil
		if d := eval.Evaluate(req, &without); !grants(d.Verdict) {
			side := graph.SideResource
			if kind == graph.Assumes {
				side = graph.SideTrust
			}
			fx := sideFix(kind, "", side, req, set.Resource, t, resource, resource+" "+policy, "")
			out = appendSide(out, &fx, rw.guardsResource())
		}
	}
	sortFixes(out)
	return out
}

// appendSide adds a side; a guarded side (the principal could write the
// grant back, SCORING.md §4.2) keeps only its resolve steps: a guard is
// about changes the principal could undo, and resolving is not a change but
// knowledge (Phase 6 review).
func appendSide(out []graph.Fix, fx *graph.Fix, guarded bool) []graph.Fix {
	if !guarded {
		return append(out, *fx)
	}
	if !fx.Pending() {
		return out
	}
	return append(out, graph.Fix{Side: fx.Side, Kind: graph.FixResolve, Policy: fx.Policy, Resource: fx.Resource, Resolve: fx.Resolve})
}

// sideFix prices one policy side from the statements that grant on it. An
// identity side names the granting policies; a resource side names the
// resource whose policy changes (label). A grant that applies only UNKNOWN
// is resolved (cost 0, no patch); on the identity side, a grant from an AWS
// managed policy in the snapshot is detached (one change per attachment,
// holder's); the other statements are narrowed or revoked (SCORING.md §4.1).
func sideFix(kind graph.Kind, sub, side string, req *eval.Request, docs []*model.PolicyDocument, t *grantTarget, resource, label, holder string) graph.Fix {
	var stmts []*model.Statement
	var ids []string
	var refs []graph.Grant
	fx := graph.Fix{Side: side, Resource: resource}
	for _, gd := range eval.GrantingDetail(req, docs) {
		id := gd.Doc.ID()
		switch {
		case gd.Applies == model.Unknown:
			r := resolution(&gd)
			if !slices.Contains(fx.Resolve, r) {
				fx.Resolve = append(fx.Resolve, r)
			}
		case side == graph.SideIdentity && awsManaged(id):
			if !slices.ContainsFunc(fx.Detach, func(d graph.Detach) bool { return d.Policy == id }) {
				fx.Detach = append(fx.Detach, graph.Detach{
					Policy: id, Group: holder + " " + id,
					Cost: scoring.FixCost(kind, sub, side, graph.FixRevoke),
				})
			}
		default:
			stmts = append(stmts, gd.Statement)
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
			refs = append(refs, graph.Grant{Policy: id, Statement: gd.Statement.Index()})
		}
	}
	grantIDs := slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return !model.IsGrantDoc(id) })
	fx.Policy = sideLabel(label, resource, ids, grantIDs)
	switch {
	case len(stmts) > 0, len(fx.Resolve) == 0 && len(fx.Detach) == 0:
		// With no granting statement found the grant cannot be shown broad.
		fx.Kind = sideKind(stmts, side, t, grantIDs)
		fx.Cost = scoring.FixCost(kind, sub, side, fx.Kind)
		fx.Grants = refs
	case len(fx.Detach) == 0:
		fx.Kind = graph.FixResolve
	}
	return fx
}

// sideKind: a KMS grant cannot be edited, only revoked or retired (no
// UpdateGrant), so a side with one is a revoke whatever it names
// (SCORING.md §4.1); otherwise fixKind decides.
func sideKind(stmts []*model.Statement, side string, t *grantTarget, grantIDs []string) string {
	if len(grantIDs) > 0 {
		return graph.FixRevoke
	}
	return fixKind(stmts, side, t)
}

// sideLabel names what a side's fix changes: the policies of an identity
// side (label ""), the resource whose policy changes otherwise; a KMS grant
// is named itself, since revoking it is the change.
func sideLabel(label, resource string, ids, grantIDs []string) string {
	switch {
	case label == "":
		slices.Sort(ids)
		return strings.Join(ids, ", ")
	case len(grantIDs) == 0:
		return label
	}
	slices.Sort(grantIDs)
	if len(grantIDs) < len(ids) {
		return resource + " key policy, " + strings.Join(grantIDs, ", ")
	}
	return strings.Join(grantIDs, ", ")
}

// awsManaged: an AWS managed policy (arn:<partition>:iam::aws:policy/...),
// which no customer can edit.
func awsManaged(id string) bool {
	_, rest, ok := strings.Cut(id, ":iam::aws:policy/")
	return ok && strings.HasPrefix(id, "arn:") && rest != ""
}

// resolution names what decides an UNKNOWN grant (SCORING.md §4.1).
func resolution(gd *eval.GrantDetail) graph.Resolution {
	id := gd.Doc.ID()
	r := graph.Resolution{Policy: id, Command: "--plan"}
	switch {
	case awsManaged(id):
		r.Command = "tools/refresh-managed-policies"
	case strings.HasSuffix(id, "#key-policy-not-in-input"):
		r.Policy = strings.TrimSuffix(id, "#key-policy-not-in-input")
		r.Command = "scan the key's Terraform or plan, or a snapshot of its account"
	default:
		for _, u := range gd.Unresolved {
			if c, ok := resolveCommand(&u); ok {
				r.Command = c
				break
			}
		}
	}
	return r
}

// resolveCommand: a Terraform variable is set with -var-file; another value
// not known statically needs a plan; a context key is assumed in darb.yaml.
func resolveCommand(u *eval.Unresolved) (string, bool) {
	if ids := model.UnresolvedIDs(u.Reason); len(ids) > 0 {
		if name, ok := strings.CutPrefix(ids[0], "var."); ok {
			return "-var-file (" + name + ")", true
		}
		return "--plan", true
	}
	if u.Element == "Condition" && strings.Contains(u.Key, ":") && !model.ContainsUnresolved(u.Key) {
		return `assume: {"` + u.Key + `": [...]} in darb.yaml`, true
	}
	return "", false
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

func sortFixes(fs []graph.Fix) {
	slices.SortFunc(fs, func(a, c graph.Fix) int {
		if ta, tc := a.Total(), c.Total(); ta != tc {
			return int(ta - tc)
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
