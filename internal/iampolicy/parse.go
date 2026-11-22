package iampolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/r3oof-900/darb/internal/model"
)

// Options identify the policy being parsed.
type Options struct {
	ID     string // ARN, Terraform address, or a label used in evidence
	Kind   model.PolicyKind
	Source model.SourceLocation
	// Placeholders: the caller wrote unresolved placeholders into the text
	// itself, as plain text. Every placeholder in the decoded document must
	// then be one of those; one produced by JSON escapes ("${darb:...")
	// is input. Without it, any placeholder is input.
	Placeholders bool
}

// ErrReservedText is returned when a document contains darb's reserved
// placeholder text that the caller did not write: it is invalid input.
var ErrReservedText = errors.New("iampolicy: input contains the reserved text " + model.UnresolvedPrefix + "...}")

// Parse decodes an IAM policy JSON document. It never panics: any input that
// is not a valid policy yields an error wrapping ErrMalformed (structure) or
// model.ErrInvalidPolicy (semantics).
func Parse(data []byte, opts *Options) (*model.PolicyDocument, error) {
	v, err := decode(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", opts.ID, err)
	}
	if n := countReserved(v); n > 0 && (!opts.Placeholders || n > bytes.Count(data, []byte(model.UnresolvedPrefix))) {
		return nil, fmt.Errorf("%s: %w", opts.ID, ErrReservedText)
	}
	in, err := toPolicyInput(v, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", opts.ID, err)
	}
	return model.NewPolicyDocument(in)
}

func toPolicyInput(v any, opts *Options) (*model.PolicyInput, error) {
	doc, ok := v.(*object)
	if !ok {
		return nil, fmt.Errorf("%w: the document must be a JSON object", ErrMalformed)
	}
	in := &model.PolicyInput{ID: opts.ID, Kind: opts.Kind, Source: opts.Source}
	for _, f := range doc.fields {
		var err error
		switch f.key {
		case "Version":
			in.Version, err = str(f.val, "Version")
		case "Id":
			_, err = str(f.val, "Id")
		case "Statement":
			in.Statements, err = statements(f.val)
		default:
			err = fmt.Errorf("%w: unknown top-level element %q", ErrMalformed, f.key)
		}
		if err != nil {
			return nil, err
		}
	}
	if _, ok := doc.get("Statement"); !ok {
		return nil, fmt.Errorf("%w: missing Statement", ErrMalformed)
	}
	return in, nil
}

func statements(v any) ([]*model.StatementInput, error) {
	items, ok := v.([]any)
	if !ok {
		items = []any{v} // a single statement object is allowed
	}
	out := make([]*model.StatementInput, 0, len(items))
	for i, item := range items {
		st, err := statement(item)
		if err != nil {
			return nil, fmt.Errorf("statement %d: %w", i, err)
		}
		out = append(out, st)
	}
	return out, nil
}

func statement(v any) (*model.StatementInput, error) {
	o, ok := v.(*object)
	if !ok {
		return nil, fmt.Errorf("%w: a statement must be a JSON object", ErrMalformed)
	}
	st := &model.StatementInput{}
	for _, f := range o.fields {
		if err := setElement(st, f); err != nil {
			return nil, err
		}
	}
	return st, nil
}

func setElement(st *model.StatementInput, f field) error {
	var err error
	switch f.key {
	case "Sid":
		st.Sid, err = str(f.val, "Sid")
	case "Effect":
		st.Effect, err = effect(f.val)
	case "Principal":
		st.Principal, err = principal(f.val)
	case "NotPrincipal":
		st.NotPrincipal, err = principal(f.val)
	case "Action":
		st.Action, err = stringList(f.val, "Action")
	case "NotAction":
		st.NotAction, err = stringList(f.val, "NotAction")
	case "Resource":
		st.Resource, err = stringList(f.val, "Resource")
	case "NotResource":
		st.NotResource, err = stringList(f.val, "NotResource")
	case "Condition":
		st.Conditions, err = conditions(f.val)
	default:
		err = fmt.Errorf("%w: unknown statement element %q", ErrMalformed, f.key)
	}
	return err
}

func effect(v any) (model.Effect, error) {
	s, err := str(v, "Effect")
	switch {
	case err != nil:
		return 0, err
	case s == "Allow":
		return model.EffectAllow, nil
	case s == "Deny":
		return model.EffectDeny, nil
	}
	return 0, fmt.Errorf("%w: Effect must be \"Allow\" or \"Deny\", got %q", ErrMalformed, s)
}

func principal(v any) (*model.PrincipalSpec, error) {
	if s, ok := v.(string); ok {
		if s != "*" {
			return nil, fmt.Errorf("%w: a string Principal must be \"*\", got %q", ErrMalformed, s)
		}
		return model.NewPrincipalSpec(true, nil), nil
	}
	o, ok := v.(*object)
	if !ok || len(o.fields) == 0 {
		return nil, fmt.Errorf("%w: Principal must be \"*\" or a non-empty object", ErrMalformed)
	}
	var refs []model.PrincipalRef
	for _, f := range o.fields {
		t := model.PrincipalType(f.key)
		switch t {
		case model.PrincipalAWS, model.PrincipalService, model.PrincipalFederated, model.PrincipalCanonicalUser:
		default:
			return nil, fmt.Errorf("%w: unknown principal type %q", ErrMalformed, f.key)
		}
		values, err := stringList(f.val, "Principal."+f.key)
		if err != nil {
			return nil, err
		}
		for _, val := range values {
			refs = append(refs, model.PrincipalRef{Type: t, Value: val})
		}
	}
	return model.NewPrincipalSpec(false, refs), nil
}

// conditions decodes {"Operator": {"key": value-or-values}}. Values may be
// strings, numbers or booleans; they are kept as their JSON text, which is
// how IAM compares them. An empty value list is kept empty; the evaluator
// reports it as UNKNOWN (docs/DESIGN.md section 6.3).
func conditions(v any) ([]model.Condition, error) {
	ops, ok := v.(*object)
	if !ok {
		return nil, fmt.Errorf("%w: Condition must be an object", ErrMalformed)
	}
	var out []model.Condition
	for _, op := range ops.fields {
		keys, ok := op.val.(*object)
		if !ok {
			return nil, fmt.Errorf("%w: Condition.%s must be an object", ErrMalformed, op.key)
		}
		for _, k := range keys.fields {
			values, err := conditionValues(k.val)
			if err != nil {
				return nil, fmt.Errorf("condition %s on %s: %w", op.key, k.key, err)
			}
			out = append(out, model.NewCondition(op.key, k.key, values))
		}
	}
	return out, nil
}

func conditionValues(v any) ([]string, error) {
	items, isList := v.([]any)
	if !isList {
		items = []any{v}
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		switch x := item.(type) {
		case string:
			out = append(out, x)
		case json.Number:
			out = append(out, x.String())
		case bool:
			out = append(out, fmt.Sprint(x))
		default:
			return nil, fmt.Errorf("%w: condition values must be strings, numbers or booleans", ErrMalformed)
		}
	}
	return out, nil
}

func str(v any, name string) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s must be a string", ErrMalformed, name)
	}
	return s, nil
}

// stringList accepts a string or a non-empty array of strings.
func stringList(v any, name string) ([]string, error) {
	if s, ok := v.(string); ok {
		return []string{s}, nil
	}
	items, ok := v.([]any)
	if !ok || len(items) == 0 {
		return nil, fmt.Errorf("%w: %s must be a string or a non-empty array of strings", ErrMalformed, name)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%w: %s must contain only strings", ErrMalformed, name)
		}
		out = append(out, s)
	}
	return out, nil
}

// countReserved counts the placeholders in a decoded document's keys and
// string values. A placeholder the caller wrote appears as plain text in the
// input too, so it is counted once in each; one that only decoding produced
// is counted here alone.
func countReserved(v any) int {
	switch x := v.(type) {
	case string:
		return model.CountUnresolved(x)
	case []any:
		n := 0
		for _, item := range x {
			n += countReserved(item)
		}
		return n
	case *object:
		n := 0
		for _, f := range x.fields {
			n += model.CountUnresolved(f.key) + countReserved(f.val)
		}
		return n
	}
	return 0
}
