package collect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ReservedText starts every unresolved-value placeholder darb creates
// (model.UnresolvedPrefix; TestReservedTextMatchesModel keeps them equal).
// Only the normalizer may create placeholders: input text containing it is
// invalid input, rejected with its file:line (docs/DESIGN.md section 4.6).
const ReservedText = "${darb:unresolved:"

// ErrReservedText is the error for input that contains ReservedText.
var ErrReservedText = errors.New("input contains the reserved text " + ReservedText + "...}")

// ReservedTextError locates reserved text in a file.
type ReservedTextError struct {
	Line int // 1-based
}

func (e *ReservedTextError) Error() string {
	return fmt.Sprintf("line %d: %s", e.Line, ErrReservedText.Error())
}

func (e *ReservedTextError) Unwrap() error { return ErrReservedText }

// ContainsReserved reports whether a decoded input string contains the
// reserved text, also once percent-decoded (IAM returns policy documents
// URL-encoded, so "%24%7Bdarb..." is the same text).
func ContainsReserved(s string) bool {
	if strings.Contains(s, ReservedText) {
		return true
	}
	if !strings.Contains(s, "%") {
		return false
	}
	d, err := url.PathUnescape(s)
	return err == nil && strings.Contains(d, ReservedText)
}

// FindReservedJSON returns the line of the first JSON string, key or value,
// that contains the reserved text after JSON decoding (so escapes such as
// a backslash-u dollar sign are seen as what they stand for). Invalid JSON
// is left to the real decoder: it reports no reserved text.
//
// A string that is itself a JSON document (a snapshot's bucket policy, an
// IAM policy URL-encoded inside get-account-authorization-details) is
// searched too, up to a few levels: its escapes are decoded only there.
func FindReservedJSON(data []byte) (int, bool) { return findReservedJSON(data, 0) }

const maxEmbedded = 3

func findReservedJSON(data []byte, depth int) (int, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		before := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			return 0, false
		}
		if s, ok := tok.(string); ok && (ContainsReserved(s) || embeddedReserved(s, depth)) {
			// The token starts after any whitespace and separators that
			// follow the previous one.
			start := int(before) + bytes.IndexByte(data[before:], '"')
			return 1 + bytes.Count(data[:start], []byte("\n")), true
		}
	}
}

// embeddedReserved searches s as a JSON document, as is and percent-decoded.
func embeddedReserved(s string, depth int) bool {
	if depth >= maxEmbedded {
		return false
	}
	candidates := []string{s}
	if d, err := url.QueryUnescape(s); err == nil && d != s {
		candidates = append(candidates, d)
	}
	for _, c := range candidates {
		if t := strings.TrimSpace(c); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
			if _, found := findReservedJSON([]byte(t), depth+1); found {
				return true
			}
		}
	}
	return false
}
