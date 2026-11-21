package posture

import (
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/eval/match"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/rules"
)

// BroadGrant is the rule of a sensitive action granted on every resource, or to every
// principal (DESIGN.md §8.1, decided in the Phase 5 review). A remediation
// that only blocks one path (a mitigation) leaves the grant; this finding
// keeps it visible, so the scan is not clean while it exists.
const BroadGrant = "CLAPA-POST-008"

// sensitiveActions read data or take an identity.
func sensitiveActions() []string {
	return []string{"kms:Decrypt", "sts:AssumeRole", "iam:PassRole", "s3:GetObject", "secretsmanager:GetSecretValue", "ssm:GetParameter"}
}

// orgOnlyKeys scope a grant to an organization or account, not to a target:
// a statement with only these conditions is still broad.
func orgOnlyKeys() []string {
	return []string{
		"aws:principalorgid", "aws:principalorgpaths", "aws:principalaccount",
		"aws:resourceorgid", "aws:resourceorgpaths", "aws:resourceaccount", "aws:sourceaccount", "aws:sourceorgid",
	}
}

// covered: the sensitive actions the statement allows (definitely).
func covered(s *model.Statement) []string {
	acts, negated := s.Actions()
	var out []string
	for _, a := range sensitiveActions() {
		m := match.Action(acts, a)
		if negated {
			m = m.Not()
		}
		if m == model.True {
			out = append(out, a)
		}
	}
	return out
}

// onlyOrgConditions: no condition, or only organization/account keys.
func onlyOrgConditions(s *model.Statement) bool {
	return !slices.ContainsFunc(s.Conditions(), func(c model.Condition) bool {
		return !slices.Contains(orgOnlyKeys(), strings.ToLower(c.Key()))
	})
}

// everyResource: a Resource of "*", or an ARN pattern whose resource part
// is "*", "*/*" or "<type>/*" for a resource type of a non-S3 service
// (every resource of that type); NotResource is broad too.
func everyResource(s *model.Statement) bool {
	rs, negated := s.Resources()
	if negated {
		return true
	}
	return slices.ContainsFunc(rs, func(r string) bool {
		if r == "*" {
			return true
		}
		parts := strings.SplitN(r, ":", 6)
		if len(parts) < 6 {
			return false
		}
		res := parts[5]
		if res == "*" || res == "*/*" {
			return true
		}
		// "<type>/*": every resource of a type. S3 has no type prefix: the
		// part before the slash is a bucket name ("b/*" is one bucket).
		typ, rest, found := strings.Cut(res, "/")
		return parts[2] != "s3" && found && rest == "*" && slices.Contains(resourceTypes(), typ)
	})
}

// resourceTypes are the ARN resource-type prefixes of the sensitive actions'
// services ("key/*" is every KMS key, "role/*" every role).
func resourceTypes() []string {
	return []string{"key", "alias", "role", "user", "policy", "secret", "parameter"}
}

// everyPrincipal: Principal "*" or {"AWS": "*"}.
func everyPrincipal(s *model.Statement) bool {
	spec, negated := s.Principal()
	if spec == nil || negated {
		return false
	}
	return spec.Wildcard() || slices.ContainsFunc(spec.Refs(), func(r model.PrincipalRef) bool { return r.Value == "*" })
}

// boundaryKeeps: without a boundary every action stays; with one, only an
// action the boundary also allows on every resource (it limits the grant).
func boundaryKeeps(b *model.PolicyDocument, action string) bool {
	if b == nil {
		return true
	}
	keeps := false
	for _, s := range b.Statements() {
		if !slices.Contains(covered(s), action) || !everyResource(s) {
			continue
		}
		if s.Effect() == model.EffectDeny {
			return false
		}
		keeps = true
	}
	return keeps
}

type broadHit struct {
	location model.SourceLocation
	evidence []string
}

// broadSet collects the broad grants per principal or resource.
type broadSet map[model.ID]*broadHit

func (b broadSet) add(target model.ID, doc *model.PolicyDocument, s *model.Statement, actions []string, what string) {
	h, ok := b[target]
	if !ok {
		h = &broadHit{location: *doc.Source()}
		b[target] = h
	}
	h.evidence = append(h.evidence, doc.ID()+" "+s.Label()+": "+strings.Join(actions, ", ")+" "+what)
}

// attached: identity statements on every resource (that the boundary
// keeps), resource-policy statements to every principal.
func (b broadSet) attached(ap *model.AttachedPolicy, boundary *model.PolicyDocument) {
	for _, s := range ap.Doc.Statements() {
		if s.Effect() != model.EffectAllow || !onlyOrgConditions(s) {
			continue
		}
		acts := covered(s)
		switch {
		case ap.Doc.Kind() == model.PolicyIdentity && everyResource(s):
			acts = slices.DeleteFunc(acts, func(a string) bool { return !boundaryKeeps(boundary, a) })
			if len(acts) > 0 {
				b.add(ap.Target, ap.Doc, s, acts, "on every resource")
			}
		case ap.Doc.Kind() == model.PolicyResource && everyPrincipal(s) && len(acts) > 0:
			b.add(ap.Target, ap.Doc, s, acts, "to every principal")
		}
	}
}

// trust: a trust policy letting every principal assume the role.
func (b broadSet) trust(t *model.TrustRelationship) {
	if t.Policy() == nil {
		return
	}
	for _, s := range t.Policy().Statements() {
		if s.Effect() == model.EffectAllow && onlyOrgConditions(s) && everyPrincipal(s) && slices.Contains(covered(s), "sts:AssumeRole") {
			b.add(t.Role(), t.Policy(), s, []string{"sts:AssumeRole"}, "to every principal")
		}
	}
}

// broadGrants: identity statements granting a sensitive action on every
// resource (that the boundary keeps), and resource or trust policies
// granting one to every principal; both with no condition other than an
// organization or account scope. One finding per principal or resource.
func broadGrants(in *rules.Input) []hit {
	inv := in.Inventory
	boundaries := map[model.ID]*model.PolicyDocument{}
	for _, b := range inv.Boundaries {
		boundaries[b.Target] = b.Doc
	}
	set := broadSet{}
	for _, ap := range inv.Policies {
		set.attached(ap, boundaries[ap.Target])
	}
	for _, t := range inv.Trusts {
		set.trust(t)
	}
	names := map[model.ID]string{}
	for _, p := range inv.Principals {
		names[p.ID()] = p.Identity()
	}
	for _, r := range inv.Resources {
		names[r.ID()] = r.ARN()
	}
	ids := make([]model.ID, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	out := make([]hit, 0, len(ids))
	for _, id := range ids {
		out = append(out, hit{resource: names[id], id: id, location: set[id].location, evidence: set[id].evidence})
	}
	return out
}
