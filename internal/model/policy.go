package model

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrInvalidPolicy is returned for structurally invalid policies or statements.
var ErrInvalidPolicy = errors.New("model: invalid policy")

// Policy language versions. Only Version2012 enables policy variables.
const (
	Version2012 = "2012-10-17"
	Version2008 = "2008-10-17"
)

// Effect is a statement's effect.
type Effect uint8

// Effects. The zero value is invalid.
const (
	EffectAllow Effect = iota + 1
	EffectDeny
)

// String returns "Allow" or "Deny".
func (e Effect) String() string {
	if e == EffectDeny {
		return "Deny"
	}
	return "Allow"
}

// PolicyKind says what role a policy plays in authorization.
type PolicyKind uint8

// Policy kinds. A role trust policy is a resource-based policy on the role.
const (
	PolicyIdentity PolicyKind = iota + 1
	PolicyResource
	PolicyBoundary
	PolicySession
	PolicySCP
	PolicyRCP
)

// String returns a short lowercase name.
func (k PolicyKind) String() string {
	switch k {
	case PolicyIdentity:
		return "identity"
	case PolicyResource:
		return "resource"
	case PolicyBoundary:
		return "boundary"
	case PolicySession:
		return "session"
	case PolicySCP:
		return "scp"
	case PolicyRCP:
		return "rcp"
	}
	return "invalid"
}

// PrincipalType is a key of the Principal element.
type PrincipalType string

// Principal types.
const (
	PrincipalAWS           PrincipalType = "AWS"
	PrincipalService       PrincipalType = "Service"
	PrincipalFederated     PrincipalType = "Federated"
	PrincipalCanonicalUser PrincipalType = "CanonicalUser"
)

// PrincipalRef is one entry of a Principal element, e.g. {AWS, role ARN}.
type PrincipalRef struct {
	Type  PrincipalType
	Value string
}

// PrincipalSpec is a Principal or NotPrincipal element. Wildcard means the
// bare string form "Principal": "*".
type PrincipalSpec struct {
	wildcard bool
	refs     []PrincipalRef
}

// NewPrincipalSpec copies and sorts refs.
func NewPrincipalSpec(wildcard bool, refs []PrincipalRef) *PrincipalSpec {
	rs := slices.Clone(refs)
	slices.SortFunc(rs, func(a, b PrincipalRef) int {
		if c := strings.Compare(string(a.Type), string(b.Type)); c != 0 {
			return c
		}
		return strings.Compare(a.Value, b.Value)
	})
	return &PrincipalSpec{wildcard: wildcard, refs: rs}
}

// Wildcard reports the "Principal": "*" form.
func (p *PrincipalSpec) Wildcard() bool { return p.wildcard }

// Refs returns a copy of the entries, sorted by type then value.
func (p *PrincipalSpec) Refs() []PrincipalRef { return slices.Clone(p.refs) }

// Condition is one (operator, key, values) triple of a Condition block.
type Condition struct {
	operator string
	key      string
	values   []string
}

// NewCondition copies values. Operator and key are kept exactly as written.
func NewCondition(operator, key string, values []string) Condition {
	return Condition{operator: operator, key: key, values: slices.Clone(values)}
}

// Operator returns the operator as written, e.g. "ForAnyValue:StringLikeIfExists".
func (c *Condition) Operator() string { return c.operator }

// Key returns the condition key as written.
func (c *Condition) Key() string { return c.key }

// Values returns a copy of the policy values.
func (c *Condition) Values() []string { return slices.Clone(c.values) }

// StatementInput is the mutable input to NewStatement.
type StatementInput struct {
	Sid          string
	Effect       Effect
	Principal    *PrincipalSpec
	NotPrincipal *PrincipalSpec
	Action       []string
	NotAction    []string
	Resource     []string
	NotResource  []string
	Conditions   []Condition
}

// Statement is an immutable policy statement.
type Statement struct {
	sid          string
	index        int
	effect       Effect
	principal    *PrincipalSpec
	notPrincipal bool
	actions      []string
	notAction    bool
	resources    []string
	notResource  bool
	conditions   []Condition
}

// NewStatement validates and copies in. index is the statement's position in
// its policy, used in evidence when the statement has no Sid.
func NewStatement(index int, in *StatementInput) (*Statement, error) {
	switch {
	case in.Effect != EffectAllow && in.Effect != EffectDeny:
		return nil, fmt.Errorf("%w: statement %d: invalid Effect", ErrInvalidPolicy, index)
	case (len(in.Action) == 0) == (len(in.NotAction) == 0):
		return nil, fmt.Errorf("%w: statement %d: exactly one of Action or NotAction is required", ErrInvalidPolicy, index)
	case len(in.Resource) > 0 && len(in.NotResource) > 0:
		return nil, fmt.Errorf("%w: statement %d: both Resource and NotResource", ErrInvalidPolicy, index)
	case in.Principal != nil && in.NotPrincipal != nil:
		return nil, fmt.Errorf("%w: statement %d: both Principal and NotPrincipal", ErrInvalidPolicy, index)
	}
	s := &Statement{
		sid: in.Sid, index: index, effect: in.Effect,
		principal: in.Principal, notPrincipal: in.NotPrincipal != nil,
		actions: slices.Clone(in.Action), notAction: len(in.NotAction) > 0,
		resources: slices.Clone(in.Resource), notResource: len(in.NotResource) > 0,
	}
	if s.notPrincipal {
		s.principal = in.NotPrincipal
	}
	if s.notAction {
		s.actions = slices.Clone(in.NotAction)
	}
	if s.notResource {
		s.resources = slices.Clone(in.NotResource)
	}
	for i := range in.Conditions {
		c := &in.Conditions[i]
		s.conditions = append(s.conditions, NewCondition(c.operator, c.key, c.values))
	}
	return s, nil
}

// Sid returns the statement ID ("" if none).
func (s *Statement) Sid() string { return s.sid }

// Index returns the statement's position in its policy.
func (s *Statement) Index() int { return s.index }

// Effect returns Allow or Deny.
func (s *Statement) Effect() Effect { return s.effect }

// Principal returns the Principal or NotPrincipal element (nil if neither)
// and whether it is NotPrincipal.
func (s *Statement) Principal() (spec *PrincipalSpec, negated bool) {
	return s.principal, s.notPrincipal
}

// Actions returns a copy of Action (or NotAction, with negated = true).
func (s *Statement) Actions() (actions []string, negated bool) {
	return slices.Clone(s.actions), s.notAction
}

// Resources returns a copy of Resource (or NotResource, with negated = true).
// An empty result means the statement has no resource element.
func (s *Statement) Resources() (resources []string, negated bool) {
	return slices.Clone(s.resources), s.notResource
}

// Conditions returns a copy of the conditions.
func (s *Statement) Conditions() []Condition { return slices.Clone(s.conditions) }

// Label is "Sid" if set, else "#index".
func (s *Statement) Label() string {
	if s.sid != "" {
		return s.sid
	}
	return fmt.Sprintf("#%d", s.index)
}

// PolicyInput is the mutable input to NewPolicyDocument.
type PolicyInput struct {
	ID         string
	Kind       PolicyKind
	Version    string
	Source     SourceLocation
	Statements []*StatementInput
}

// PolicyDocument is an immutable policy.
type PolicyDocument struct {
	id         string
	kind       PolicyKind
	version    string
	source     SourceLocation
	statements []*Statement
}

// NewPolicyDocument validates in. Resource-based policies and RCPs require a
// Principal or NotPrincipal in every statement (RCPs must use "Principal":
// "*", AWS Organizations User Guide › "RCP syntax"); all other kinds forbid them.
func NewPolicyDocument(in *PolicyInput) (*PolicyDocument, error) {
	if in.Kind < PolicyIdentity || in.Kind > PolicyRCP {
		return nil, fmt.Errorf("%w: %s: invalid policy kind", ErrInvalidPolicy, in.ID)
	}
	d := &PolicyDocument{id: in.ID, kind: in.Kind, version: in.Version, source: in.Source}
	needsPrincipal := in.Kind == PolicyResource || in.Kind == PolicyRCP
	for i, si := range in.Statements {
		hasPrincipal := si.Principal != nil || si.NotPrincipal != nil
		if hasPrincipal != needsPrincipal {
			return nil, fmt.Errorf("%w: %s: statement %d: Principal is required in resource-based policies and RCPs, and forbidden in %s policies",
				ErrInvalidPolicy, in.ID, i, in.Kind)
		}
		s, err := NewStatement(i, si)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", in.ID, err)
		}
		d.statements = append(d.statements, s)
	}
	return d, nil
}

// ID returns the policy's identifier (ARN, Terraform address, or a label).
func (d *PolicyDocument) ID() string { return d.id }

// Kind returns the policy kind.
func (d *PolicyDocument) Kind() PolicyKind { return d.kind }

// Version returns the policy language version as written ("" if absent).
func (d *PolicyDocument) Version() string { return d.version }

// VariablesEnabled reports whether ${...} policy variables are interpreted.
// IAM User Guide › "IAM policy elements: Variables and tags": variables need
// Version 2012-10-17; otherwise they are literal text.
func (d *PolicyDocument) VariablesEnabled() bool { return d.version == Version2012 }

// Source returns where the policy was defined.
func (d *PolicyDocument) Source() *SourceLocation { s := d.source; return &s }

// Statements returns the statements in document order.
func (d *PolicyDocument) Statements() []*Statement { return slices.Clone(d.statements) }
