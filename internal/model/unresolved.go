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
//
// Only the normalizer creates placeholders (normalize.Builder.Placeholder
// registers each one). Input text that contains the prefix is rejected as
// invalid input with its file:line, so a file cannot turn a definite answer
// into UNKNOWN by writing the reserved text (docs/DESIGN.md section 4.6).
const unresolvedPrefix = "${clapa:unresolved:"

// UnresolvedPrefix is the reserved text every placeholder starts with.
const UnresolvedPrefix = unresolvedPrefix

// UnresolvedPlaceholder returns the placeholder for unresolved value id.
func UnresolvedPlaceholder(id string) string {
	return unresolvedPrefix + id + "}"
}

// ContainsUnresolved reports whether s contains an unresolved placeholder.
func ContainsUnresolved(s string) bool {
	return strings.Contains(s, unresolvedPrefix)
}

// CountUnresolved counts the placeholders in s.
func CountUnresolved(s string) int { return strings.Count(s, unresolvedPrefix) }

// UnresolvedIDs returns the ids of the placeholders in s, in order. An
// unterminated placeholder's id runs to the end of s.
func UnresolvedIDs(s string) []string {
	var out []string
	for {
		i := strings.Index(s, unresolvedPrefix)
		if i < 0 {
			return out
		}
		s = s[i+len(unresolvedPrefix):]
		j := strings.IndexByte(s, '}')
		if j < 0 {
			return append(out, s)
		}
		out = append(out, s[:j])
		s = s[j+1:]
	}
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
