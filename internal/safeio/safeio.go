package safeio

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Limits bound what a single input may cost (docs/THREAT_MODEL.md, DoS).
type Limits struct {
	MaxFileBytes int64
	MaxDepth     int // JSON/YAML nesting
}

// DefaultLimits returns 16 MiB per file and nesting depth 64.
func DefaultLimits() Limits { return Limits{MaxFileBytes: 16 << 20, MaxDepth: 64} }

// Errors callers branch on.
var (
	ErrOutsideRoot = errors.New("safeio: path is outside the scan root")
	ErrNotRegular  = errors.New("safeio: not a regular file")
	ErrTooLarge    = errors.New("safeio: file exceeds the size limit")
	ErrTooDeep     = errors.New("safeio: nesting exceeds the depth limit")
)

// ReadFile reads root/rel. rel must stay inside root, also after resolving
// symlinks; the target must be a regular file within the size limit.
func ReadFile(root, rel string, lim Limits) ([]byte, error) {
	path, err := confine(root, rel)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("safeio: %s: %w", rel, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, rel)
	}
	if info.Size() > lim.MaxFileBytes {
		return nil, fmt.Errorf("%w: %s is %d bytes (limit %d)", ErrTooLarge, rel, info.Size(), lim.MaxFileBytes)
	}
	f, err := os.Open(path) //nolint:gosec // G304: path is confined to the scan root above.
	if err != nil {
		return nil, fmt.Errorf("safeio: %s: %w", rel, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, lim.MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("safeio: %s: %w", rel, err)
	}
	if int64(len(data)) > lim.MaxFileBytes {
		return nil, fmt.Errorf("%w: %s grew while reading", ErrTooLarge, rel)
	}
	return data, nil
}

// confine returns the absolute path of rel under root, rejecting escapes by
// ".." or by symlinks that resolve outside root.
func confine(root, rel string) (string, error) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("safeio: root %s: %w", root, err)
	}
	joined := filepath.Join(realRoot, filepath.FromSlash(rel))
	if !within(realRoot, joined) {
		return "", fmt.Errorf("%w: %s", ErrOutsideRoot, rel)
	}
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return "", fmt.Errorf("safeio: %s: %w", rel, err)
	}
	if !within(realRoot, resolved) {
		return "", fmt.Errorf("%w: %s resolves outside the root", ErrOutsideRoot, rel)
	}
	return resolved, nil
}

func within(root, path string) bool {
	r, err := filepath.Rel(root, path)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) && !filepath.IsAbs(r)
}

// Walk lists files under root whose extension (case-insensitive) is in exts,
// as sorted slash-separated paths relative to root. Hidden directories
// (".git", ".terraform", ...) are skipped and symlinked directories are not
// followed.
func Walk(root string, exts []string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !slices.Contains(exts, strings.ToLower(filepath.Ext(d.Name()))) {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return fmt.Errorf("safeio: %s: %w", p, relErr)
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("safeio: walk %s: %w", root, err)
	}
	slices.Sort(out)
	return out, nil
}

// CheckJSONDepth rejects JSON nested deeper than max, without decoding it.
// Brackets inside strings are ignored.
func CheckJSONDepth(data []byte, maxDepth int) error {
	depth, inString, escaped := 0, false, false
	for _, c := range data {
		switch {
		case inString:
			inString, escaped = stringState(c, escaped)
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			depth++
			if depth > maxDepth {
				return fmt.Errorf("%w (%d)", ErrTooDeep, maxDepth)
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return nil
}

func stringState(c byte, escaped bool) (inString, nextEscaped bool) {
	switch {
	case escaped:
		return true, false
	case c == '\\':
		return true, true
	case c == '"':
		return false, false
	}
	return true, false
}
