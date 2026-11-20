package model

import "strings"

// Unresolved source values (docs/DESIGN.md section 4.1).
//
// A value a collector could not resolve (e.g. "var.x" without a value in
// static HCL) is never turned into guessed text. Inside policy documents it
// is replaced by the placeholder ${clapa:unresolved:<id>}, which the
// evaluator always treats as UNKNOWN, wherever it appears (Action, Resource,
// Principal, condition key or value) and whatever the policy Version. The
// "clapa:" namespace cannot collide with AWS condition keys.
const unresolvedPrefix = "${clapa:unresolved:"

// UnresolvedPlaceholder returns the placeholder for unresolved value id.
func UnresolvedPlaceholder(id string) string {
	return unresolvedPrefix + id + "}"
}

// ContainsUnresolved reports whether s contains an unresolved placeholder.
func ContainsUnresolved(s string) bool {
	return strings.Contains(s, unresolvedPrefix)
}

// SplitUnresolved returns the known pieces of s around its placeholders:
// "a${clapa:unresolved:x}b" gives ["a", "b"]. A string without placeholders
// gives [s]. An unterminated placeholder runs to the end of s.
func SplitUnresolved(s string) []string {
	var out []string
	for {
		i := strings.Index(s, unresolvedPrefix)
		if i < 0 {
			return append(out, s)
		}
		out = append(out, s[:i])
		rest := s[i+len(unresolvedPrefix):]
		j := strings.IndexByte(rest, '}')
		if j < 0 {
			return append(out, "")
		}
		s = rest[j+1:]
	}
}

// AnyUnresolved reports whether any of ss contains an unresolved placeholder.
func AnyUnresolved(ss []string) bool {
	for _, s := range ss {
		if ContainsUnresolved(s) {
			return true
		}
	}
	return false
}
