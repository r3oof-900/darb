package patch

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
)

// A file is edited by splicing byte ranges that a parser located (hclsyntax
// ranges, YAML node lines, JSON offsets), never by pattern matching, and
// everything outside the ranges is kept byte for byte: line endings (LF or
// CRLF), a UTF-8 byte order mark, comments and spacing. New text uses the
// file's own line ending and indentation.

var bom = []byte{0xEF, 0xBB, 0xBF}

// text is one file being edited: its bytes without a BOM, and the splices.
type text struct {
	path    string
	hadBOM  bool
	src     []byte
	splices []splice
}

type splice struct {
	start, end int
	repl       string
}

func newText(path string, data []byte) *text {
	t := &text{path: path, src: data}
	if bytes.HasPrefix(data, bom) {
		t.hadBOM, t.src = true, data[len(bom):]
	}
	return t
}

// newline is the file's line ending: CRLF when it has any, LF otherwise.
func (t *text) newline() string {
	if bytes.Contains(t.src, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

// lineStart is the offset of the start of the line holding off.
func (t *text) lineStart(off int) int {
	return bytes.LastIndexByte(t.src[:off], '\n') + 1
}

// lineEnd is the offset just past the line ending of the line holding off
// (len(src) on the last line).
func (t *text) lineEnd(off int) int {
	if i := bytes.IndexByte(t.src[off:], '\n'); i >= 0 {
		return off + i + 1
	}
	return len(t.src)
}

// indentAt is the leading whitespace of the line holding off.
func (t *text) indentAt(off int) string {
	ls := t.lineStart(off)
	i := ls
	for i < len(t.src) && (t.src[i] == ' ' || t.src[i] == '\t') {
		i++
	}
	return string(t.src[ls:i])
}

// onlySpaceBefore: nothing but blanks between the line start and off.
func (t *text) onlySpaceBefore(off int) bool {
	return strings.TrimLeft(string(t.src[t.lineStart(off):off]), " \t") == ""
}

func (t *text) replace(start, end int, repl string) {
	t.splices = append(t.splices, splice{start, end, repl})
}

// deleteLines removes whole lines from the line of start through the line
// of end (inclusive of its line ending).
func (t *text) deleteLines(start, end int) {
	t.replace(t.lineStart(start), t.lineEnd(end), "")
}

// result applies the splices; they must not overlap.
func (t *text) result() ([]byte, error) {
	ss := slices.Clone(t.splices)
	slices.SortFunc(ss, func(a, b splice) int {
		if a.start != b.start {
			return b.start - a.start
		}
		return b.end - a.end
	})
	out := slices.Clone(t.src)
	limit := len(out)
	for _, s := range ss {
		if s.end > limit || s.start > s.end {
			return nil, fmt.Errorf("patch: %s: overlapping edits", t.path)
		}
		out = slices.Concat(out[:s.start], []byte(s.repl), out[s.end:])
		limit = s.start
	}
	if t.hadBOM {
		out = slices.Concat(bom, out)
	}
	return out, nil
}
