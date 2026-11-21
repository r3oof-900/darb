package patch

import (
	"encoding/json"
	"errors"
	"fmt"
)

// jnode is a JSON value with the byte range it occupies, so a policy written
// as JSON text (a heredoc) is edited at exact offsets.
type jnode struct {
	kind       byte // 'o' object, 'a' array, 's' string, 'v' other scalar
	start, end int
	str        string // decoded, for strings
	keys       []jmember
	items      []*jnode
}

type jmember struct {
	name string
	val  *jnode
}

func (n *jnode) member(name string) *jnode {
	for _, m := range n.keys {
		if m.name == name {
			return m.val
		}
	}
	return nil
}

type jparser struct {
	s   []byte
	pos int
}

var errJSON = errors.New("not a JSON policy")

// parseJSON parses s, which must hold exactly one JSON value.
func parseJSON(s []byte) (*jnode, error) {
	p := &jparser{s: s}
	n, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skip()
	if p.pos != len(s) {
		return nil, fmt.Errorf("%w: text after the document at offset %d", errJSON, p.pos)
	}
	return n, nil
}

func (p *jparser) skip() {
	for p.pos < len(p.s) {
		switch p.s[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}

const maxDepth = 64

func (p *jparser) value(depth int) (*jnode, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: nested too deeply", errJSON)
	}
	p.skip()
	if p.pos >= len(p.s) {
		return nil, fmt.Errorf("%w: unexpected end", errJSON)
	}
	switch p.s[p.pos] {
	case '{':
		return p.object(depth)
	case '[':
		return p.array(depth)
	case '"':
		return p.str()
	}
	return p.scalar()
}

func (p *jparser) object(depth int) (*jnode, error) {
	n := &jnode{kind: 'o', start: p.pos}
	p.pos++
	for {
		p.skip()
		if p.pos < len(p.s) && p.s[p.pos] == '}' && len(n.keys) == 0 {
			p.pos++
			n.end = p.pos
			return n, nil
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		p.skip()
		if p.pos >= len(p.s) || p.s[p.pos] != ':' {
			return nil, fmt.Errorf("%w: expected ':' at offset %d", errJSON, p.pos)
		}
		p.pos++
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		n.keys = append(n.keys, jmember{name: k.str, val: v})
		if done, err := p.next('}'); err != nil || done {
			n.end = p.pos
			return n, err
		}
	}
}

func (p *jparser) array(depth int) (*jnode, error) {
	n := &jnode{kind: 'a', start: p.pos}
	p.pos++
	for {
		p.skip()
		if p.pos < len(p.s) && p.s[p.pos] == ']' && len(n.items) == 0 {
			p.pos++
			n.end = p.pos
			return n, nil
		}
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		n.items = append(n.items, v)
		if done, err := p.next(']'); err != nil || done {
			n.end = p.pos
			return n, err
		}
	}
}

// next consumes ',' (more to come) or the closing bracket (done).
func (p *jparser) next(closing byte) (bool, error) {
	p.skip()
	if p.pos >= len(p.s) {
		return false, fmt.Errorf("%w: unexpected end", errJSON)
	}
	switch p.s[p.pos] {
	case ',':
		p.pos++
		return false, nil
	case closing:
		p.pos++
		return true, nil
	}
	return false, fmt.Errorf("%w: unexpected %q at offset %d", errJSON, p.s[p.pos], p.pos)
}

func (p *jparser) str() (*jnode, error) {
	if p.pos >= len(p.s) || p.s[p.pos] != '"' {
		return nil, fmt.Errorf("%w: expected a string at offset %d", errJSON, p.pos)
	}
	start := p.pos
	p.pos++
	for p.pos < len(p.s) {
		switch p.s[p.pos] {
		case '\\':
			p.pos += 2
			continue
		case '"':
			p.pos++
			var v string
			if err := json.Unmarshal(p.s[start:p.pos], &v); err != nil {
				return nil, fmt.Errorf("%w: bad string at offset %d", errJSON, start)
			}
			return &jnode{kind: 's', start: start, end: p.pos, str: v}, nil
		}
		p.pos++
	}
	return nil, fmt.Errorf("%w: unterminated string", errJSON)
}

func (p *jparser) scalar() (*jnode, error) {
	start := p.pos
	for p.pos < len(p.s) && !isDelim(p.s[p.pos]) {
		p.pos++
	}
	var v any
	if p.pos == start || json.Unmarshal(p.s[start:p.pos], &v) != nil {
		return nil, fmt.Errorf("%w: bad value at offset %d", errJSON, start)
	}
	return &jnode{kind: 'v', start: start, end: p.pos}, nil
}

func isDelim(c byte) bool {
	switch c {
	case ',', '}', ']', ' ', '\t', '\r', '\n', ':':
		return true
	}
	return false
}
