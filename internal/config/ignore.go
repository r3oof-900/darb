package config

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// Suppression silences one finding (by fingerprint) until it expires.
// docs/DESIGN.md section 8: reason, owner and expiry are mandatory.
type Suppression struct {
	Fingerprint string `json:"fingerprint"`
	Reason      string `json:"reason"`
	Owner       string `json:"owner"`
	Expires     string `json:"expires"` // YYYY-MM-DD, inclusive
}

type ignoreFile struct {
	Suppressions []Suppression `json:"suppressions"`
}

// ParseIgnore decodes .darb-ignore.yaml.
func ParseIgnore(data []byte) ([]Suppression, error) {
	var f ignoreFile
	if err := yaml.UnmarshalStrict(data, &f); err != nil {
		return nil, fmt.Errorf("%w: .darb-ignore.yaml: %w", ErrInvalid, err)
	}
	var problems []string
	seen := map[string]bool{}
	for i, s := range f.Suppressions {
		if s.Fingerprint == "" || s.Reason == "" || s.Owner == "" || s.Expires == "" {
			problems = append(problems, fmt.Sprintf("suppressions[%d]: fingerprint, reason, owner and expires are required", i))
		}
		if _, err := time.Parse(time.DateOnly, s.Expires); s.Expires != "" && err != nil {
			problems = append(problems, fmt.Sprintf("suppressions[%d]: expires must be YYYY-MM-DD", i))
		}
		if seen[s.Fingerprint] {
			problems = append(problems, fmt.Sprintf("suppressions[%d]: duplicate fingerprint", i))
		}
		seen[s.Fingerprint] = true
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	out := slices.Clone(f.Suppressions)
	slices.SortFunc(out, func(a, b Suppression) int { return strings.Compare(a.Fingerprint, b.Fingerprint) })
	return out, nil
}

// Active reports whether s still applies on day now (expiry day included).
// Expired suppressions re-fire.
func (s *Suppression) Active(now time.Time) bool {
	exp, err := time.Parse(time.DateOnly, s.Expires)
	if err != nil {
		return false
	}
	return !now.UTC().Truncate(24 * time.Hour).After(exp)
}
