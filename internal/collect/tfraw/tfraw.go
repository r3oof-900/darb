package tfraw

import (
	"slices"
	"strings"
)

// Pos is a source position (1-based lines; 0 when unknown).
type Pos struct {
	File      string
	StartLine int
	EndLine   int
}

// Kind is the kind of a Value.
type Kind uint8

// Value kinds.
const (
	KNull Kind = iota
	KString
	KNumber
	KBool
	KList
	KObject
	// KRef is a reference to another resource's attribute ("aws_kms_key.pii.arn"),
	// kept symbolic so the normalizer links it to the canonical node.
	KRef
	// KTemplate is a string built from literal parts and references,
	// e.g. "${aws_s3_bucket.b.arn}/*".
	KTemplate
	// KUnresolved is a value static analysis could not determine. It is never
	// guessed; Expr holds the source text.
	KUnresolved
	// KUnknownAfterApply is a plan value only known after apply.
	KUnknownAfterApply
)

// Value is a Terraform value, possibly partially symbolic.
type Value struct {
	Kind   Kind
	Str    string // KString; number text for KNumber
	Bool   bool
	List   []*Value // KList; parts for KTemplate
	Obj    *Object
	Ref    *Ref
	Expr   string // source text for KUnresolved/KUnknownAfterApply; for KObject, "jsonencode" when the object was JSON-encoded
	Pos    Pos
	Reason string // why a value is unresolved
}

// Ref is a symbolic reference to "<address>.<attr>".
type Ref struct {
	Address string // e.g. aws_kms_key.pii, data.aws_iam_policy_document.trust, module.m.aws_iam_role.r
	Attr    string // e.g. arn, json, id
}

// String renders "address.attr".
func (r *Ref) String() string { return r.Address + "." + r.Attr }

// Object is a map with deterministic key order.
type Object struct {
	fields map[string]*Value
}

// NewObject returns an empty object.
func NewObject() *Object { return &Object{fields: map[string]*Value{}} }

// Set stores a field.
func (o *Object) Set(key string, v *Value) { o.fields[key] = v }

// Get returns a field.
func (o *Object) Get(key string) (*Value, bool) {
	v, ok := o.fields[key]
	return v, ok
}

// Keys returns the field names, sorted.
func (o *Object) Keys() []string {
	keys := make([]string, 0, len(o.fields))
	for k := range o.fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Str returns a literal string field, if present and known.
func (o *Object) Str(key string) (string, bool) {
	v, ok := o.fields[key]
	if !ok || v.Kind != KString {
		return "", false
	}
	return v.Str, true
}

// Blocks returns the nested blocks (list of objects) under key.
func (o *Object) Blocks(key string) []*Object {
	v, ok := o.fields[key]
	if !ok {
		return nil
	}
	if v.Kind == KObject {
		return []*Object{v.Obj}
	}
	var out []*Object
	for _, item := range v.List {
		if item.Kind == KObject {
			out = append(out, item.Obj)
		}
	}
	return out
}

// Literal helpers.

// String returns a KString value.
func String(s string) *Value { return &Value{Kind: KString, Str: s} }

// Unresolved returns a KUnresolved value.
func Unresolved(expr, reason string, pos Pos) *Value {
	return &Value{Kind: KUnresolved, Expr: expr, Reason: reason, Pos: pos}
}

// Resource is one Terraform resource or data source instance.
type Resource struct {
	Address  string // full address, with module path and instance key
	Mode     string // "managed" or "data"
	Type     string
	Name     string
	Module   string // "" for the root module, else "module.a.module.b"
	Index    string // instance key: "", "0", "\"a\"", or "[*]" when not expanded (static count/for_each)
	Provider string // provider configuration key, e.g. "aws" or "aws.east"
	// Root identifies the Terraform root: the plan file, or the directory
	// evaluated as a root module in static mode. Addresses are unique per Root.
	Root  string
	Attrs *Object
	Pos   Pos
}

// ConfigAddress is the address without the instance key.
func (r *Resource) ConfigAddress() string {
	i := strings.LastIndex(r.Address, "[")
	if i < 0 || !strings.HasSuffix(r.Address, "]") {
		return r.Address
	}
	return r.Address[:i]
}

// Provider describes an AWS provider configuration.
type Provider struct {
	Key     string // "aws", "aws.east"
	Region  *Value
	Account *Value // from allowed_account_ids or assume_role ARN when known
}

// Module is what a Terraform collector returns.
type Module struct {
	Source    string // "plan" or "hcl"
	Resources []*Resource
	Providers []*Provider
}

// Sort orders resources and providers by address for determinism.
func (m *Module) Sort() {
	slices.SortFunc(m.Resources, func(a, b *Resource) int { return strings.Compare(a.Address, b.Address) })
	slices.SortFunc(m.Providers, func(a, b *Provider) int { return strings.Compare(a.Key, b.Key) })
}
