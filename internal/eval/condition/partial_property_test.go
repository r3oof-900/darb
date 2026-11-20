package condition

import (
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/r3oof-900/clapa/internal/model"
)

// A definite answer from the known parts of a request value is accepted only
// if no substitution of the unknown part changes it (DESIGN.md §4.6,
// scenario 3): for random values with an unresolved part, random policy
// values and substitutions — random ones and ones built to match the policy
// value — "no" means every substitution gives no, and "yes" every one yes.
func TestPartialValueProperty(t *testing.T) {
	alphabet := []string{"a", "b", "-", ":", "/", "p"}
	str := func(label string, extra ...string) *rapid.Generator[string] {
		return rapid.Custom(func(t *rapid.T) string {
			parts := rapid.SliceOfN(rapid.SampledFrom(append(alphabet, extra...)), 0, 6).Draw(t, label)
			return strings.Join(parts, "")
		})
	}
	rapid.Check(t, func(t *rapid.T) {
		op := rapid.SampledFrom([]string{"StringEquals", "StringNotEquals", "StringLike", "StringNotLike"}).Draw(t, "op")
		like := strings.Contains(op, "Like")
		var pv string
		if like {
			pv = str("pv", "*", "?").Draw(t, "pv")
		} else {
			pv = str("pv").Draw(t, "pv")
		}
		prefix, suffix := str("prefix").Draw(t, "prefix"), str("suffix").Draw(t, "suffix")
		cond := model.NewCondition(op, "k", []string{pv})
		decide := func(v string) model.Tri {
			c := NewContext(&Input{Default: StateAbsent, Present: map[string][]string{"k": {v}}})
			return Evaluate(&cond, c, stubExpander{}).Value
		}
		got := decide(prefix + model.UnresolvedPlaceholder("x") + suffix)
		if got == model.Unknown {
			return
		}
		subs := []string{"", str("sub").Draw(t, "sub")}
		// Built to match: the policy value minus the known parts, with any
		// wildcard filled in.
		target := strings.NewReplacer("*", "", "?", "a").Replace(pv)
		if strings.HasPrefix(target, prefix) && strings.HasSuffix(target[len(prefix):], suffix) {
			subs = append(subs, target[len(prefix):len(target)-len(suffix)])
		}
		for _, sub := range subs {
			if concrete := decide(prefix + sub + suffix); concrete != got {
				t.Fatalf("%s %q on %q<x>%q decided %s, but x=%q gives %s", op, pv, prefix, suffix, got, sub, concrete)
			}
		}
	})
}

// The case from the Phase 4 review: the bucket name may be anything, so it
// may be payments.
func TestUnknownBucketNameMayMatch(t *testing.T) {
	c := NewContext(&Input{Default: StateAbsent, Present: map[string][]string{
		"aws:SourceArn": {"arn:aws:s3:::" + model.UnresolvedPlaceholder("X") + "-pii"},
	}})
	for _, op := range []string{"StringEquals", "StringNotEquals", "StringLike"} {
		cond := model.NewCondition(op, "aws:SourceArn", []string{"arn:aws:s3:::payments-pii"})
		if got := Evaluate(&cond, c, stubExpander{}).Value; got != model.Unknown {
			t.Errorf("%s: %s, want UNKNOWN", op, got)
		}
	}
}
