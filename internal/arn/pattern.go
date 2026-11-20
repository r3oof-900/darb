package arn

// Mode selects how wildcards treat the ':' segment separator.
type Mode uint8

const (
	// Plain lets '*' match any run of characters and '?' any one character.
	// Used for actions and for StringLike condition values.
	Plain Mode = iota
	// Resource applies IAM Resource-element semantics. Wildcards stay within one
	// colon-separated segment, except that a '*' that is the last character of
	// a segment (followed by ':' or the end of the pattern) may also match
	// across colons. IAM User Guide › "IAM JSON policy elements: Resource" ›
	// "Including wildcard characters (* or ?) in the resource ARN".
	Resource
)

type tokKind uint8

const (
	tokLit tokKind = iota
	tokOne
	tokStar
)

type token struct {
	kind tokKind
	r    rune
}

// Pattern is a compiled wildcard pattern. The zero value matches only "".
type Pattern struct {
	mode Mode
	toks []token
}

// Compile treats '*' and '?' in s as wildcards; every other rune is literal.
func Compile(s string, m Mode) Pattern {
	toks := make([]token, 0, len(s))
	for _, r := range s {
		switch r {
		case '*':
			toks = append(toks, token{kind: tokStar})
		case '?':
			toks = append(toks, token{kind: tokOne})
		default:
			toks = append(toks, token{kind: tokLit, r: r})
		}
	}
	return Pattern{mode: m, toks: toks}
}

// Literal returns a pattern in which every rune of s, including '*' and '?',
// matches only itself. Used for policy-variable values and escapes such as ${*}.
func Literal(s string, m Mode) Pattern {
	toks := make([]token, 0, len(s))
	for _, r := range s {
		toks = append(toks, token{kind: tokLit, r: r})
	}
	return Pattern{mode: m, toks: toks}
}

// Append returns a new pattern: p followed by q, in p's mode.
func (p Pattern) Append(q Pattern) Pattern {
	toks := make([]token, 0, len(p.toks)+len(q.toks))
	toks = append(toks, p.toks...)
	toks = append(toks, q.toks...)
	return Pattern{mode: p.mode, toks: toks}
}

// SplitN splits the pattern at literal sep runes into at most n parts, like
// strings.SplitN. Wildcards never act as separators. Parts keep p's mode.
func (p Pattern) SplitN(sep rune, n int) []Pattern {
	var out []Pattern
	start := 0
	for i, t := range p.toks {
		if len(out) == n-1 {
			break
		}
		if t.kind == tokLit && t.r == sep {
			out = append(out, Pattern{mode: p.mode, toks: append([]token(nil), p.toks[start:i]...)})
			start = i + 1
		}
	}
	return append(out, Pattern{mode: p.mode, toks: append([]token(nil), p.toks[start:]...)})
}

// HasWildcard reports whether the pattern contains '*' or '?' wildcards.
func (p Pattern) HasWildcard() bool {
	for _, t := range p.toks {
		if t.kind != tokLit {
			return true
		}
	}
	return false
}

// Match reports whether s matches the whole pattern. It runs in
// O(len(pattern) × len(s)) time and O(len(s)) space for any input.
func (p Pattern) Match(s string) bool {
	rs := []rune(s)
	n := len(rs)
	prev := make([]bool, n+1)
	cur := make([]bool, n+1)
	prev[0] = true
	for i, t := range p.toks {
		if t.kind == tokStar {
			span := p.starSpans(i)
			cur[0] = prev[0]
			for j := 1; j <= n; j++ {
				cur[j] = prev[j] || (cur[j-1] && (span || rs[j-1] != ':'))
			}
		} else {
			cur[0] = false
			for j := 1; j <= n; j++ {
				cur[j] = prev[j-1] && p.tokenMatches(t, rs[j-1])
			}
		}
		prev, cur = cur, prev
	}
	return prev[n]
}

// starSpans reports whether the '*' at index i may match ':'.
func (p Pattern) starSpans(i int) bool {
	if p.mode == Plain {
		return true
	}
	next := i + 1
	return next == len(p.toks) || (p.toks[next].kind == tokLit && p.toks[next].r == ':')
}

func (p Pattern) tokenMatches(t token, r rune) bool {
	if t.kind == tokOne {
		return p.mode == Plain || r != ':'
	}
	return t.r == r
}

// String renders the pattern with wildcards as '*' and '?'. Literal '*' or
// '?' runes (from Literal) are rendered as "${*}" and "${?}" so the rendering
// is unambiguous.
func (p Pattern) String() string {
	out := make([]rune, 0, len(p.toks))
	for _, t := range p.toks {
		switch {
		case t.kind == tokStar:
			out = append(out, '*')
		case t.kind == tokOne:
			out = append(out, '?')
		case t.r == '*' || t.r == '?':
			out = append(out, '$', '{', t.r, '}')
		default:
			out = append(out, t.r)
		}
	}
	return string(out)
}
