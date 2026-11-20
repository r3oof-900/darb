package condition

import "strings"

// Family groups operators by how values are compared.
type Family uint8

// Operator families (IAM User Guide › "IAM JSON policy elements: Condition operators").
const (
	FamilyString Family = iota + 1
	FamilyNumeric
	FamilyDate
	FamilyBool
	FamilyBinary
	FamilyIP
	FamilyARN
	FamilyNull
)

// Comparison is the positive comparison an operator performs.
type Comparison uint8

// Comparisons. Negated operators use the positive comparison and invert it.
const (
	CmpEquals Comparison = iota + 1
	CmpEqualsIgnoreCase
	CmpLike
	CmpLess
	CmpLessEquals
	CmpGreater
	CmpGreaterEquals
)

// SetOp is the multivalued-key qualifier.
type SetOp uint8

// Set qualifiers.
const (
	SetNone SetOp = iota
	SetAnyValue
	SetAllValues
)

// Operator is a parsed condition operator.
type Operator struct {
	Family   Family
	Cmp      Comparison
	Negated  bool
	IfExists bool
	Set      SetOp
}

type base struct {
	family  Family
	cmp     Comparison
	negated bool
}

// lookupBase maps an operator name (without qualifier or IfExists) to its
// meaning. A switch keeps the core free of package-level tables.
func lookupBase(name string) (base, bool) {
	switch name {
	case "StringEquals":
		return base{FamilyString, CmpEquals, false}, true
	case "StringNotEquals":
		return base{FamilyString, CmpEquals, true}, true
	case "StringEqualsIgnoreCase":
		return base{FamilyString, CmpEqualsIgnoreCase, false}, true
	case "StringNotEqualsIgnoreCase":
		return base{FamilyString, CmpEqualsIgnoreCase, true}, true
	case "StringLike":
		return base{FamilyString, CmpLike, false}, true
	case "StringNotLike":
		return base{FamilyString, CmpLike, true}, true
	case "Bool":
		return base{FamilyBool, CmpEquals, false}, true
	case "BinaryEquals":
		return base{FamilyBinary, CmpEquals, false}, true
	case "IpAddress":
		return base{FamilyIP, CmpEquals, false}, true
	case "NotIpAddress":
		return base{FamilyIP, CmpEquals, true}, true
	case "ArnEquals", "ArnLike":
		// Both are case-sensitive and accept wildcards per ARN segment.
		return base{FamilyARN, CmpLike, false}, true
	case "ArnNotEquals", "ArnNotLike":
		return base{FamilyARN, CmpLike, true}, true
	case "Null":
		return base{FamilyNull, CmpEquals, false}, true
	}
	return ordered(name)
}

// ordered handles the Numeric* and Date* operators.
func ordered(name string) (base, bool) {
	var fam Family
	switch {
	case strings.HasPrefix(name, "Numeric"):
		fam, name = FamilyNumeric, strings.TrimPrefix(name, "Numeric")
	case strings.HasPrefix(name, "Date"):
		fam, name = FamilyDate, strings.TrimPrefix(name, "Date")
	default:
		return base{}, false
	}
	switch name {
	case "Equals":
		return base{fam, CmpEquals, false}, true
	case "NotEquals":
		return base{fam, CmpEquals, true}, true
	case "LessThan":
		return base{fam, CmpLess, false}, true
	case "LessThanEquals":
		return base{fam, CmpLessEquals, false}, true
	case "GreaterThan":
		return base{fam, CmpGreater, false}, true
	case "GreaterThanEquals":
		return base{fam, CmpGreaterEquals, false}, true
	}
	return base{}, false
}

// ParseOperator parses e.g. "ForAnyValue:StringLikeIfExists". Operator names
// are case-sensitive, as in IAM. Null takes neither a set qualifier nor
// IfExists.
func ParseOperator(s string) (Operator, bool) {
	var op Operator
	switch {
	case strings.HasPrefix(s, "ForAnyValue:"):
		op.Set, s = SetAnyValue, strings.TrimPrefix(s, "ForAnyValue:")
	case strings.HasPrefix(s, "ForAllValues:"):
		op.Set, s = SetAllValues, strings.TrimPrefix(s, "ForAllValues:")
	}
	if name, ok := strings.CutSuffix(s, "IfExists"); ok {
		op.IfExists, s = true, name
	}
	b, ok := lookupBase(s)
	if !ok || (b.family == FamilyNull && (op.IfExists || op.Set != SetNone)) {
		return Operator{}, false
	}
	op.Family, op.Cmp, op.Negated = b.family, b.cmp, b.negated
	return op, true
}
