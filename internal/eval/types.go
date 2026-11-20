package eval

import (
	"github.com/r3oof-900/clapa/internal/eval/condition"
	"github.com/r3oof-900/clapa/internal/eval/match"
	"github.com/r3oof-900/clapa/internal/model"
)

// Verdict is the outcome of an authorization decision.
type Verdict uint8

// Verdicts. Unknown is never rendered as "safe".
const (
	ImplicitDeny Verdict = iota
	Deny
	Unknown
	Allow
)

// String returns the spec's names.
func (v Verdict) String() string {
	switch v {
	case Allow:
		return "ALLOW"
	case Deny:
		return "DENY"
	case Unknown:
		return "UNKNOWN"
	case ImplicitDeny:
		return "IMPLICIT_DENY"
	}
	return "INVALID"
}

// Grants reports the access a verdict represents, for ordering: ALLOW >
// UNKNOWN > DENY = IMPLICIT_DENY. Used by property tests and the path engine.
func (v Verdict) Grants() int {
	switch v {
	case Allow:
		return 2
	case Unknown:
		return 1
	case Deny, ImplicitDeny:
		return 0
	}
	return 0
}

// Request is one authorization question.
type Request struct {
	Principal match.RequestPrincipal
	Action    string
	Resource  string
	// ResourceAccount is the account that owns the resource; "" when not
	// known, in which case same- vs cross-account is decided only if both
	// interpretations agree.
	ResourceAccount string
	// Context holds the request context keys; nil means every key is unknown.
	Context *condition.Context
}

// PolicySet holds every policy that applies to a request.
type PolicySet struct {
	Identity []*model.PolicyDocument
	Resource []*model.PolicyDocument
	// Boundary is the principal's permissions boundary; nil means none.
	Boundary *model.PolicyDocument
	// Session holds session policies; nil means the session has none.
	Session []*model.PolicyDocument
	// SCPs and RCPs: one entry per level of the organization (root, each OU,
	// the account); every level must allow. nil means not modelled.
	SCPs [][]*model.PolicyDocument
	RCPs [][]*model.PolicyDocument
	// ResourcePolicyRequired is set for resources whose policy must allow
	// (directly or by delegating to the account): KMS keys and role trust policies.
	ResourcePolicyRequired bool
}

// StatementRef identifies a statement that contributed to a decision.
type StatementRef struct {
	PolicyID string
	Kind     model.PolicyKind
	Sid      string
	Index    int
	Effect   model.Effect
	Source   model.SourceLocation
	Applies  model.Tri
}

// Unresolved records why a statement could not be decided.
type Unresolved struct {
	PolicyID  string
	Kind      model.PolicyKind
	Statement string // Sid or "#index"
	Element   string // "Principal", "Resource" or "Condition"
	Operator  string
	Key       string
	Reason    string
}

// Component is a policy type that must allow for access.
type Component uint8

// Components, in evaluation order.
const (
	CompIdentity Component = iota + 1
	CompResource
	CompBoundary
	CompSession
	CompSCP
	CompRCP
)

// String names the component.
func (c Component) String() string {
	switch c {
	case CompIdentity:
		return "identity policy"
	case CompResource:
		return "resource-based policy"
	case CompBoundary:
		return "permissions boundary"
	case CompSession:
		return "session policy"
	case CompSCP:
		return "service control policy"
	case CompRCP:
		return "resource control policy"
	}
	return "invalid"
}

// Decision is the result of Evaluate.
type Decision struct {
	Verdict Verdict
	// Contributing: the deny statements for DENY, the allowing statements for
	// ALLOW, and the undecided statements for UNKNOWN. Sorted.
	Contributing []StatementRef
	// Unresolved lists what made the decision UNKNOWN.
	Unresolved []Unresolved
	// Missing lists required components that did not (definitely) allow.
	Missing []Component
	// Assumptions lists inputs that were not modelled (e.g. no SCPs given).
	Assumptions []string
}
