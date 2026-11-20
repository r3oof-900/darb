package match

import (
	"strings"

	"github.com/r3oof-900/clapa/internal/arn"
	"github.com/r3oof-900/clapa/internal/model"
)

// Expander resolves ${...} policy variables in Resource patterns. See
// condition.Expander for the meaning of the returned Tri.
type Expander interface {
	ExpandPattern(s string, m arn.Mode) (arn.Pattern, model.Tri)
}

// Action reports whether action matches any pattern. Matching is
// case-insensitive with '*' and '?' wildcards over the whole
// "service:action" string (IAM User Guide › "IAM JSON policy elements: Action").
// Policy variables are not interpreted in Action; a pattern that was not
// resolved in the source (model.ContainsUnresolved) matches Unknown.
func Action(patterns []string, action string) model.Tri {
	a := strings.ToLower(action)
	acc := model.False
	for _, p := range patterns {
		if model.ContainsUnresolved(p) {
			acc = acc.Or(model.Unknown)
			continue
		}
		acc = acc.Or(model.TriOf(arn.Compile(strings.ToLower(p), arn.Plain).Match(a)))
	}
	return acc
}

// Resource reports whether resource matches any pattern, using Resource-mode
// wildcards (case-sensitive, segment-aware). A pattern whose variables are
// unresolved makes the result Unknown unless another pattern matches.
func Resource(patterns []string, resource string, x Expander) model.Tri {
	acc := model.False
	for _, raw := range patterns {
		p, ok := x.ExpandPattern(raw, arn.Resource)
		if ok == model.True {
			ok = Value(p, resource)
		}
		// ok is now False for a pattern that references an absent key (it
		// matches nothing), Unknown for an unresolved one.
		acc = acc.Or(ok)
	}
	return acc
}

// Value matches a pattern against a value that may hold unresolved parts
// (e.g. a bucket ARN whose name came from an unresolved variable):
// False only when no substitution of the unknown parts could match, True
// when the pattern matches whatever they are, Unknown otherwise. A fully
// known value is matched exactly.
func Value(p arn.Pattern, value string) model.Tri {
	if !model.ContainsUnresolved(value) {
		return model.TriOf(p.Match(value))
	}
	pieces := model.SplitUnresolved(value)
	v := arn.Literal(pieces[0], arn.Plain)
	for _, piece := range pieces[1:] {
		v = v.Append(arn.Compile("*", arn.Plain)).Append(arn.Literal(piece, arn.Plain))
	}
	if !p.Intersects(v) {
		return model.False
	}
	// "Matches whatever they are" is checked on representative fillings:
	// empty, one foreign character, and a run with segment separators.
	for _, fill := range []string{"", "\x00", "\x00:/\x00"} {
		if !p.Match(strings.Join(pieces, fill)) {
			return model.Unknown
		}
	}
	return model.True
}
