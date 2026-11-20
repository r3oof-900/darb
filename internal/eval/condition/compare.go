package condition

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/r3oof-900/clapa/internal/arn"
	"github.com/r3oof-900/clapa/internal/model"
)

// compare applies the positive comparison of op to request value r and
// policy value pv. The string explains an Unknown result.
func compare(op Operator, r, pv string, x Expander) (match model.Tri, why string) {
	if op.Cmp == CmpLike {
		p, ok := x.ExpandPattern(pv, arn.Plain)
		if ok != model.True {
			return ok, "unresolved policy variable in " + pv
		}
		if op.Family == FamilyARN {
			return model.TriOf(arnLike(p, r)), ""
		}
		return model.TriOf(p.Match(r)), ""
	}
	s, ok := x.ExpandString(pv)
	if ok != model.True {
		return ok, "unresolved policy variable in " + pv
	}
	// An if-chain rather than a switch: the string family is the fallthrough,
	// and Null never reaches compare.
	if op.Family == FamilyNumeric {
		return numericCompare(op.Cmp, r, s)
	}
	if op.Family == FamilyDate {
		return dateCompare(op.Cmp, r, s)
	}
	if op.Family == FamilyBool {
		return boolEquals(r, s)
	}
	if op.Family == FamilyBinary {
		return binaryEquals(r, s)
	}
	if op.Family == FamilyIP {
		return ipContains(r, s)
	}
	if op.Cmp == CmpEqualsIgnoreCase {
		return model.TriOf(strings.EqualFold(r, s)), ""
	}
	return model.TriOf(r == s), ""
}

// arnLike checks each of the six colon-separated ARN components separately
// (IAM User Guide › Condition operators › "Amazon Resource Name (ARN)
// condition operators"). A value that is not a six-part ARN never matches.
func arnLike(p arn.Pattern, r string) bool {
	parts := p.SplitN(':', 6)
	values := strings.SplitN(r, ":", 6)
	if len(parts) != 6 || len(values) != 6 {
		return false
	}
	for i := range parts {
		if !parts[i].Match(values[i]) {
			return false
		}
	}
	return true
}

func numericCompare(c Comparison, r, pv string) (match model.Tri, why string) {
	b, errP := strconv.ParseFloat(strings.TrimSpace(pv), 64)
	a, errR := strconv.ParseFloat(strings.TrimSpace(r), 64)
	if errP != nil || errR != nil {
		return model.Unknown, "numeric comparison of non-numeric values " + strconv.Quote(r) + " and " + strconv.Quote(pv)
	}
	return model.TriOf(order(c, cmp.Compare(a, b))), ""
}

func dateCompare(c Comparison, r, pv string) (match model.Tri, why string) {
	b, okP := parseDate(pv)
	a, okR := parseDate(r)
	if !okP || !okR {
		return model.Unknown, "date comparison of unparsable values " + strconv.Quote(r) + " and " + strconv.Quote(pv)
	}
	return model.TriOf(order(c, a.Compare(b))), ""
}

func order(c Comparison, n int) bool {
	if c == CmpLess {
		return n < 0
	}
	if c == CmpLessEquals {
		return n <= 0
	}
	if c == CmpGreater {
		return n > 0
	}
	if c == CmpGreaterEquals {
		return n >= 0
	}
	return n == 0 // CmpEquals; the string-only comparisons never reach here
}

// parseDate accepts ISO 8601 date-times, plain dates and epoch seconds
// (IAM User Guide › Condition operators › "Date condition operators").
func parseDate(s string) (t time.Time, ok bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04Z07:00", "2006-01-02"} {
		if parsed, err := time.Parse(layout, s); err == nil {
			return parsed, true
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), true
	}
	return time.Time{}, false
}

func parseBool(s string) (value, ok bool) {
	switch {
	case strings.EqualFold(s, "true"):
		return true, true
	case strings.EqualFold(s, "false"):
		return false, true
	}
	return false, false
}

func boolEquals(r, pv string) (match model.Tri, why string) {
	b, okP := parseBool(pv)
	a, okR := parseBool(r)
	if !okP || !okR {
		return model.Unknown, "Bool expects true or false"
	}
	return model.TriOf(a == b), ""
}

func binaryEquals(r, pv string) (match model.Tri, why string) {
	b, errP := base64.StdEncoding.DecodeString(pv)
	a, errR := base64.StdEncoding.DecodeString(r)
	if errP != nil || errR != nil {
		return model.Unknown, "BinaryEquals expects base64 values"
	}
	return model.TriOf(bytes.Equal(a, b)), ""
}

// ipContains: the policy value is a CIDR block (a bare address means a
// single host); the request value is an address.
func ipContains(r, pv string) (match model.Tri, why string) {
	prefix, err := netip.ParsePrefix(pv)
	if err != nil {
		addr, errA := netip.ParseAddr(pv)
		if errA != nil {
			return model.Unknown, "cannot parse IP policy value " + strconv.Quote(pv)
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	addr, err := netip.ParseAddr(r)
	if err != nil {
		return model.Unknown, "cannot parse request IP " + strconv.Quote(r)
	}
	return model.TriOf(prefix.Masked().Contains(addr)), ""
}
