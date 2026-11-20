package condition

import (
	"fmt"
	"strings"

	"github.com/r3oof-900/clapa/internal/arn"
	"github.com/r3oof-900/clapa/internal/model"
)

// Expander resolves ${...} policy variables in policy values. The returned
// Tri is True when the value was fully resolved, False when it references a
// key known to be absent (the value then matches nothing), and Unknown when a
// referenced key's value is not known.
type Expander interface {
	ExpandString(s string) (string, model.Tri)
	ExpandPattern(s string, m arn.Mode) (arn.Pattern, model.Tri)
}

// Result is the outcome of one condition. Reason explains an Unknown.
type Result struct {
	Value  model.Tri
	Reason string
}

func unknown(format string, args ...any) Result {
	return Result{Value: model.Unknown, Reason: fmt.Sprintf(format, args...)}
}

// Evaluate decides one condition against ctx (IAM User Guide › "IAM JSON
// policy elements: Condition operators" and "Single-valued vs. multivalued
// context keys"). It never guesses: an unknown key, an unsupported operator,
// an unparsable value or an unresolved variable yields Unknown.
func Evaluate(c *model.Condition, ctx *Context, x Expander) Result {
	op, ok := ParseOperator(c.Operator())
	if !ok {
		return unknown("unsupported condition operator %q", c.Operator())
	}
	if model.ContainsUnresolved(c.Key()) {
		return unknown("condition key %s was not resolved in the source", c.Key())
	}
	policy := c.Values()
	if len(policy) == 0 {
		return unknown("%s on %s has an empty value list; AWS behaviour for this is not documented", c.Operator(), c.Key())
	}
	v := ctx.Lookup(c.Key())
	if v.State == StateUnknown {
		return unknown("condition key %s is not known in the evaluation context", c.Key())
	}
	if op.Family == FamilyNull {
		return evalNull(policy, v)
	}
	e := evaluator{op: op, policy: policy, x: x}
	present := v.State == StatePresent && len(v.Values) > 0
	if op.Set == SetAnyValue {
		if !present {
			return Result{Value: model.TriOf(op.IfExists)}
		}
		return e.overRequest(v.Values, model.False, model.Tri.Or)
	}
	if op.Set == SetAllValues {
		if !present {
			return Result{Value: model.True} // documented: true for an absent or empty key
		}
		return e.overRequest(v.Values, model.True, model.Tri.And)
	}
	if !present {
		// Absent key: false, except IfExists (true) and negated operators (true).
		return Result{Value: model.TriOf(op.IfExists || op.Negated)}
	}
	if len(v.Values) > 1 {
		return unknown("%s has several values but %s has no ForAnyValue/ForAllValues qualifier", c.Key(), c.Operator())
	}
	return e.single(v.Values[0])
}

func evalNull(policy []string, v Value) Result {
	absent := model.TriOf(v.State == StateAbsent || len(v.Values) == 0)
	acc := model.False
	for _, pv := range policy {
		switch {
		case strings.EqualFold(pv, "true"):
			acc = acc.Or(absent)
		case strings.EqualFold(pv, "false"):
			acc = acc.Or(absent.Not())
		default:
			return unknown("Null expects true or false, got %q", pv)
		}
	}
	return Result{Value: acc}
}

type evaluator struct {
	op     Operator
	policy []string
	x      Expander
}

// overRequest combines single() over every request value, starting from
// start with combine (Or for ForAnyValue, And for ForAllValues).
func (e *evaluator) overRequest(values []string, start model.Tri, combine func(model.Tri, model.Tri) model.Tri) Result {
	acc := Result{Value: start}
	for _, r := range values {
		res := e.single(r)
		acc.Value = combine(acc.Value, res.Value)
		if acc.Reason == "" {
			acc.Reason = res.Reason
		}
	}
	if acc.Value != model.Unknown {
		acc.Reason = ""
	}
	return acc
}

// single: positive operators match if r matches any policy value (OR);
// negated operators are the negation of that (NOR).
func (e *evaluator) single(r string) Result {
	acc := Result{Value: model.False}
	for _, pv := range e.policy {
		m, why := compare(e.op, r, pv, e.x)
		acc.Value = acc.Value.Or(m)
		if m == model.Unknown && acc.Reason == "" {
			acc.Reason = why
		}
	}
	if e.op.Negated {
		acc.Value = acc.Value.Not()
	}
	if acc.Value != model.Unknown {
		acc.Reason = ""
	}
	return acc
}
