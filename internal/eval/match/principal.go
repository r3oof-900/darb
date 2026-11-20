package match

import (
	"strings"

	"github.com/r3oof-900/clapa/internal/arn"
	"github.com/r3oof-900/clapa/internal/model"
)

// PrincipalKind is the kind of identity making a request.
type PrincipalKind uint8

// Request principal kinds.
const (
	KindIAMUser       PrincipalKind = iota + 1
	KindAssumedRole                 // a role session; ARN is the session ARN
	KindFederatedUser               // sts:GetFederationToken session
	KindAccountRoot
	KindService     // AWS service principal, e.g. "s3.amazonaws.com"
	KindWebIdentity // OIDC/SAML federated caller of AssumeRoleWith*
	KindAnonymous
)

// RequestPrincipal describes who makes a request.
type RequestPrincipal struct {
	Kind PrincipalKind
	// ARN: user ARN, session ARN, root ARN; the service name for services;
	// the provider ARN or name for web identities.
	ARN     string
	Account string
	// SourceARN: the role ARN (with path) for an assumed-role session, or the
	// IAM user that created a federated user session.
	SourceARN     string
	CanonicalUser string
}

// Via says how a Principal element matched. Evaluation depends on it: a
// grant to the account delegates to IAM, a grant to a role ARN is still
// limited by permissions boundaries (docs/DESIGN.md section 6.1).
type Via uint8

// Match kinds, ordered from weakest to strongest.
const (
	ViaNone Via = iota
	ViaAccount
	ViaWildcard
	ViaRoleARN
	ViaFederatedUserCreator
	ViaUserARN
	ViaSessionARN
	ViaService
	ViaFederated
	ViaCanonicalUser
)

// PrincipalMatch is the outcome of matching a Principal element.
type PrincipalMatch struct {
	Value  model.Tri
	Via    Via
	Reason string
}

// Principal matches a positive Principal element (IAM User Guide › "AWS JSON
// policy elements: Principal"). Principal values take no partial wildcards:
// only "*" and {"AWS": "*"} are wildcards.
func Principal(spec *model.PrincipalSpec, p *RequestPrincipal) PrincipalMatch {
	if spec.Wildcard() {
		return PrincipalMatch{Value: model.True, Via: ViaWildcard}
	}
	if callerUnresolved(p) {
		return PrincipalMatch{Value: model.Unknown, Reason: "the caller's identity was not resolved in the source"}
	}
	best := PrincipalMatch{Value: model.False}
	for _, ref := range spec.Refs() {
		m := matchRef(ref, p)
		switch {
		case m.Value == model.True && (best.Value != model.True || m.Via > best.Via):
			best = m
		case m.Value == model.Unknown && best.Value == model.False:
			best = m
		}
	}
	return best
}

func matchRef(ref model.PrincipalRef, p *RequestPrincipal) PrincipalMatch {
	if model.ContainsUnresolved(ref.Value) {
		return PrincipalMatch{Value: model.Unknown, Reason: "principal was not resolved in the source"}
	}
	switch ref.Type {
	case model.PrincipalAWS:
		return matchAWS(ref.Value, p)
	case model.PrincipalService:
		return direct(p.Kind == KindService && strings.EqualFold(ref.Value, p.ARN), ViaService)
	case model.PrincipalFederated:
		return direct(p.Kind == KindWebIdentity && ref.Value == p.ARN, ViaFederated)
	case model.PrincipalCanonicalUser:
		return direct(p.CanonicalUser != "" && ref.Value == p.CanonicalUser, ViaCanonicalUser)
	}
	return PrincipalMatch{Value: model.False} // an unrecognised principal type matches nobody
}

// callerUnresolved: the request's own identity contains an unresolved
// placeholder (e.g. an OIDC provider ARN built from an unknown issuer).
func callerUnresolved(p *RequestPrincipal) bool {
	return model.ContainsUnresolved(p.ARN) || model.ContainsUnresolved(p.SourceARN) || model.ContainsUnresolved(p.Account)
}

func direct(ok bool, via Via) PrincipalMatch {
	if ok {
		return PrincipalMatch{Value: model.True, Via: via}
	}
	return PrincipalMatch{Value: model.False}
}

func hasAccount(k PrincipalKind) bool {
	return k == KindIAMUser || k == KindAssumedRole || k == KindFederatedUser || k == KindAccountRoot
}

func matchAWS(v string, p *RequestPrincipal) PrincipalMatch {
	if v == "*" {
		if hasAccount(p.Kind) || p.Kind == KindAnonymous {
			return PrincipalMatch{Value: model.True, Via: ViaWildcard}
		}
		return PrincipalMatch{Value: model.Unknown, Reason: `whether {"AWS": "*"} matches service or web-identity principals is not modelled`}
	}
	if acct, ok := accountOf(v); ok {
		return direct(hasAccount(p.Kind) && acct == p.Account, ViaAccount)
	}
	a, err := arn.Parse(v)
	if err != nil {
		return PrincipalMatch{Value: model.Unknown, Reason: "unresolved principal " + v + " (unique ID or invalid ARN)"}
	}
	if a.Service == "sts" {
		return matchSTS(a, v, p)
	}
	if a.Service == "iam" {
		return matchIAM(a, v, p)
	}
	return PrincipalMatch{Value: model.False}
}

// matchSTS matches session ARNs: assumed-role and federated-user.
func matchSTS(a *arn.ARN, v string, p *RequestPrincipal) PrincipalMatch {
	if strings.HasPrefix(a.Resource, "assumed-role/") {
		return direct(p.Kind == KindAssumedRole && v == p.ARN, ViaSessionARN)
	}
	if strings.HasPrefix(a.Resource, "federated-user/") {
		return direct(p.Kind == KindFederatedUser && v == p.ARN, ViaSessionARN)
	}
	return PrincipalMatch{Value: model.False}
}

// matchIAM matches role and user ARNs. A role ARN matches the role's
// sessions; a user ARN matches the user, or a federated session it created.
func matchIAM(a *arn.ARN, v string, p *RequestPrincipal) PrincipalMatch {
	if strings.HasPrefix(a.Resource, "role/") {
		return direct(p.Kind == KindAssumedRole && v == p.SourceARN, ViaRoleARN)
	}
	if !strings.HasPrefix(a.Resource, "user/") {
		return PrincipalMatch{Value: model.False}
	}
	if p.Kind == KindFederatedUser {
		return direct(v == p.SourceARN, ViaFederatedUserCreator)
	}
	return direct(p.Kind == KindIAMUser && v == p.ARN, ViaUserARN)
}

// accountOf recognises "123456789012" and "arn:<partition>:iam::123456789012:root".
func accountOf(v string) (string, bool) {
	if arn.IsAccountID(v) {
		return v, true
	}
	if a, err := arn.Parse(v); err == nil && a.IsAccountRoot() {
		return a.Account, true
	}
	return "", false
}

// NotPrincipal reports whether a NotPrincipal statement applies to p.
//
// IAM User Guide › "AWS JSON policy elements: NotPrincipal" › "Specifying
// NotPrincipal with Deny": a caller is excluded only when NotPrincipal lists
// its own ARN and its account; listing the account alone does not exclude
// other principals in it, and listing the caller without its account does
// not exclude the caller. For a role session the documented example lists
// the session ARN, the role ARN and the account; a list with the session ARN
// and account but without the role ARN is not documented and is Unknown.
func NotPrincipal(spec *model.PrincipalSpec, p *RequestPrincipal) PrincipalMatch {
	if !spec.Wildcard() && callerUnresolved(p) {
		return PrincipalMatch{Value: model.Unknown, Reason: "the caller's identity was not resolved in the source"}
	}
	l := listed(spec, p)
	m := notPrincipalListed(&l, p)
	if m.Value == model.True && l.unresolved {
		// An entry that was not resolved in the source might name the caller.
		return PrincipalMatch{Value: model.Unknown, Reason: "NotPrincipal contains an entry that was not resolved in the source"}
	}
	return m
}

func notPrincipalListed(l *listing, p *RequestPrincipal) PrincipalMatch {
	switch {
	case l.everyone:
		return PrincipalMatch{Value: model.False}
	case !hasAccount(p.Kind):
		return PrincipalMatch{Value: model.TriOf(!l.self)}
	case !l.self || !l.account:
		return PrincipalMatch{Value: model.True}
	case p.Kind == KindAssumedRole && !l.role:
		return PrincipalMatch{Value: model.Unknown, Reason: "NotPrincipal lists the session ARN and account but not the role ARN; AWS documents only the list with all three"}
	}
	return PrincipalMatch{Value: model.False}
}

// listing records which facets of the caller a NotPrincipal element names.
type listing struct {
	everyone, self, account, role, unresolved bool
}

func listed(spec *model.PrincipalSpec, p *RequestPrincipal) listing {
	l := listing{everyone: spec.Wildcard()}
	for _, ref := range spec.Refs() {
		if model.ContainsUnresolved(ref.Value) {
			l.unresolved = true
			continue
		}
		isAWS := ref.Type == model.PrincipalAWS
		if acct, ok := accountOf(ref.Value); ok && isAWS {
			l.account = l.account || (hasAccount(p.Kind) && acct == p.Account)
			l.self = l.self || (p.Kind == KindAccountRoot && acct == p.Account)
			continue
		}
		l.everyone = l.everyone || (isAWS && ref.Value == "*")
		l.self = l.self || identifies(ref, p)
		l.role = l.role || (p.Kind == KindAssumedRole && isAWS && ref.Value == p.SourceARN)
	}
	return l
}

// identifies reports whether ref names exactly the caller (not its role or account).
func identifies(ref model.PrincipalRef, p *RequestPrincipal) bool {
	switch ref.Type {
	case model.PrincipalAWS:
		return hasAccount(p.Kind) && ref.Value == p.ARN
	case model.PrincipalService:
		return p.Kind == KindService && strings.EqualFold(ref.Value, p.ARN)
	case model.PrincipalFederated:
		return p.Kind == KindWebIdentity && ref.Value == p.ARN
	case model.PrincipalCanonicalUser:
		return p.CanonicalUser != "" && ref.Value == p.CanonicalUser
	}
	return false
}
