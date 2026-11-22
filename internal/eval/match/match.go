package match

import (
	"strings"

	"github.com/r3oof-900/darb/internal/arn"
	"github.com/r3oof-900/darb/internal/model"
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
	possible, always := p.MatchPieces(model.SplitUnresolved(value))
	switch {
	case always:
		return model.True
	case possible:
		return model.Unknown
	}
	return model.False
}
