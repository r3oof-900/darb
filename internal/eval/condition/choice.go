package condition

import (
	"maps"
	"slices"
	"strings"
)

// Who decides a choice's value (DESIGN.md §6.2).
const (
	// ByAttacker: the caller sets the key in the request (TLS, headers,
	// query parameters): the evaluator takes the option best for access.
	// The attacker takes one value per key per request, whatever the
	// statements need: every option is evaluated as one whole request.
	ByAttacker = "attacker"
	// Undocumented: the documentation leaves the value open between the
	// options. When they decide alike the decision stands; otherwise it is
	// UNKNOWN, at the option best for access, naming the keys.
	Undocumented = "undocumented"
)

// Option sets every key of its choice: a key absent from the map is absent
// from the request.
type Option map[string][]string

// Choice is a set of keys decided together and the values they may take.
type Choice struct {
	Keys    []string
	Options []Option
	By      string // ByAttacker or Undocumented
	// Free: the key (one) is a free-text or numeric value the caller
	// writes: besides Options, every value a policy compares it with, and
	// Fresh, a value none names.
	Free  bool
	Fresh string
	// Source: the documentation the options come from (DESIGN.md §6.2).
	Source string
}

// Clone copies the choice.
func (c *Choice) Clone() Choice {
	out := *c
	out.Keys = slices.Clone(c.Keys)
	out.Options = make([]Option, len(c.Options))
	for i, o := range c.Options {
		cp := make(Option, len(o))
		for k, vs := range o {
			cp[k] = slices.Clone(vs)
		}
		out.Options[i] = cp
	}
	return out
}

// Choices returns the context's choices whose keys are all still unknown
// (a key the input states, or an assumption, wins over a choice).
func (c *Context) Choices() []Choice {
	var out []Choice
	for i := range c.choices {
		ch := &c.choices[i]
		if !slices.ContainsFunc(ch.Keys, func(k string) bool { return c.Lookup(k).State != StateUnknown }) {
			out = append(out, ch.Clone())
		}
	}
	return out
}

// With returns a copy of c with the keys of each choice set as its option
// says, and no choices left.
func (c *Context) With(keys []string, o Option) *Context {
	out := &Context{def: c.def, keys: maps.Clone(c.keys)}
	for _, k := range keys {
		lk := strings.ToLower(k)
		if vs, ok := o[k]; ok {
			out.keys[lk] = Value{State: StatePresent, Values: slices.Clone(vs)}
		} else {
			out.keys[lk] = Value{State: StateAbsent}
		}
	}
	return out
}
