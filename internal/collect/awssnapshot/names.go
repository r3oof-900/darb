package awssnapshot

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// A resource name becomes one path component of the bundle. Secret and
// parameter names contain "/", and AWS names are case-sensitive while
// Windows and macOS file systems usually are not, so names are escaped:
// an upper-case letter X is "!x" (as Go module paths are escaped for the
// same reason), and every byte outside [a-z0-9_+=@.-], and a leading ".",
// is "%XX". The escaped form contains no upper-case letter outside a %XX,
// so two names that differ only in case never land on the same file.

func plain(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("_+=@.-", c) >= 0
}

// escapeName returns the path component for name.
func escapeName(name string) string {
	var b strings.Builder
	for i := range len(name) {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte('!')
			b.WriteByte(c + ('a' - 'A'))
		case plain(c) && (c != '.' || i > 0):
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

var errEscape = errors.New("not an escaped name")

// unescapeName reverses escapeName; it rejects any other spelling, so one
// name has exactly one path.
func unescapeName(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '!' && i+1 < len(s) && s[i+1] >= 'a' && s[i+1] <= 'z':
			b.WriteByte(s[i+1] - ('a' - 'A'))
			i++
		case c == '%' && i+2 < len(s):
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil || strings.ToUpper(s[i+1:i+3]) != s[i+1:i+3] {
				return "", fmt.Errorf("%q: %w", s, errEscape)
			}
			b.WriteByte(byte(v))
			i += 2
		case plain(c):
			b.WriteByte(c)
		default:
			return "", fmt.Errorf("%q: %w", s, errEscape)
		}
	}
	name := b.String()
	if escapeName(name) != s {
		return "", fmt.Errorf("%q: %w", s, errEscape)
	}
	return name, nil
}
