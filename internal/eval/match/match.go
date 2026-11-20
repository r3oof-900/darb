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
// Policy variables are not interpreted in Action.
func Action(patterns []string, action string) bool {
	a := strings.ToLower(action)
	for _, p := range patterns {
		if arn.Compile(strings.ToLower(p), arn.Plain).Match(a) {
			return true
		}
	}
	return false
}

// Resource reports whether resource matches any pattern, using Resource-mode
// wildcards (case-sensitive, segment-aware). A pattern whose variables are
// unresolved makes the result Unknown unless another pattern matches.
func Resource(patterns []string, resource string, x Expander) model.Tri {
	acc := model.False
	for _, raw := range patterns {
		p, ok := x.ExpandPattern(raw, arn.Resource)
		if ok == model.True {
			ok = model.TriOf(p.Match(resource))
		}
		// ok is now False for a pattern that references an absent key (it
		// matches nothing), Unknown for an unresolved one.
		acc = acc.Or(ok)
	}
	return acc
}
