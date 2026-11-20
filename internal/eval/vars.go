package eval

import (
	"strings"

	"github.com/r3oof-900/clapa/internal/arn"
	"github.com/r3oof-900/clapa/internal/eval/condition"
	"github.com/r3oof-900/clapa/internal/model"
)

// expander resolves ${...} policy variables (IAM User Guide › "IAM policy
// elements: Variables and tags"): ${key}, ${key, 'default'}, and the escapes
// ${*}, ${?}, ${$}. Variables are interpreted only in Version 2012-10-17
// documents; elsewhere the text is literal.
type expander struct {
	ctx     *condition.Context
	enabled bool
}

// part is a piece of an expanded value: wildcard-capable text from the
// policy, or a literal substituted value.
type part struct {
	text    string
	literal bool
}

func (e expander) ExpandString(s string) (string, model.Tri) {
	parts, ok := e.expand(s)
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(p.text)
	}
	return b.String(), ok
}

func (e expander) ExpandPattern(s string, m arn.Mode) (arn.Pattern, model.Tri) {
	parts, ok := e.expand(s)
	p := arn.Literal("", m)
	for _, pt := range parts {
		if pt.literal {
			p = p.Append(arn.Literal(pt.text, m))
		} else {
			p = p.Append(arn.Compile(pt.text, m))
		}
	}
	return p, ok
}

// expand splits s into parts. The Tri is False as soon as a variable refers
// to an absent key without a default (the value then matches nothing), and
// Unknown when a referenced value is not known.
func (e expander) expand(s string) ([]part, model.Tri) {
	if model.ContainsUnresolved(s) {
		return nil, model.Unknown // a value the collector could not resolve, in any policy version
	}
	if !e.enabled {
		return []part{{text: s}}, model.True
	}
	var parts []part
	state := model.True
	rest := s
	for {
		i := strings.Index(rest, "${")
		j := strings.IndexByte(rest[max(i, 0):], '}')
		if i < 0 || j < 0 {
			return append(parts, part{text: rest}), state // no (terminated) variable left
		}
		parts = append(parts, part{text: rest[:i]})
		val, st := e.resolve(rest[i+2 : i+j])
		if st == model.False {
			return nil, model.False
		}
		state = state.And(st)
		parts = append(parts, part{text: val, literal: true})
		rest = rest[i+j+1:]
	}
}

func (e expander) resolve(name string) (string, model.Tri) {
	switch name {
	case "*", "?", "$":
		return name, model.True
	}
	key, def, hasDefault := strings.Cut(name, ",")
	key = strings.TrimSpace(key)
	def = strings.Trim(strings.TrimSpace(def), "'")
	v := e.ctx.Lookup(key)
	switch {
	case v.State == condition.StateUnknown || len(v.Values) > 1:
		return "", model.Unknown
	case len(v.Values) == 1:
		return v.Values[0], model.True
	case hasDefault:
		return def, model.True
	}
	return "", model.False
}
