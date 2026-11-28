package condition

import (
	"slices"
	"strings"
)

// State is what the analyzer knows about a context key.
type State uint8

const (
	// StateUnknown means the analyzer does not know whether the key is
	// present or what its value is. Conditions on it evaluate to Unknown.
	StateUnknown State = iota
	// StateAbsent means the key is known not to be in the request.
	StateAbsent
	// StatePresent means the key is in the request with the given values.
	StatePresent
)

// Value is one context key's state and values.
type Value struct {
	State  State
	Values []string
}

// Input is the mutable input to NewContext. Keys are case-insensitive.
type Input struct {
	// Default applies to keys not listed: StateUnknown (the honest default)
	// or StateAbsent. StatePresent is treated as StateUnknown.
	Default State
	Present map[string][]string
	Absent  []string
	Unknown []string
	// Choices: keys whose value is one of a known set (choice.go); a choice
	// counts only while every one of its keys is unknown in this context.
	Choices []Choice
}

// Context is an immutable request context.
type Context struct {
	def     State
	keys    map[string]Value
	choices []Choice
}

// NewContext copies in. When a key is listed more than once, Unknown wins
// over Present, which wins over Absent (the least certain statement wins).
func NewContext(in *Input) *Context {
	c := &Context{def: in.Default, keys: map[string]Value{}}
	if c.def == StatePresent {
		c.def = StateUnknown
	}
	for _, ch := range in.Choices {
		c.choices = append(c.choices, ch.Clone())
	}
	for _, k := range in.Absent {
		c.keys[strings.ToLower(k)] = Value{State: StateAbsent}
	}
	for k, vs := range in.Present {
		c.keys[strings.ToLower(k)] = Value{State: StatePresent, Values: slices.Clone(vs)}
	}
	for _, k := range in.Unknown {
		c.keys[strings.ToLower(k)] = Value{State: StateUnknown}
	}
	return c
}

// Lookup returns the state of key (case-insensitive).
func (c *Context) Lookup(key string) Value {
	v, ok := c.keys[strings.ToLower(key)]
	if !ok {
		return Value{State: c.def}
	}
	v.Values = slices.Clone(v.Values)
	return v
}
