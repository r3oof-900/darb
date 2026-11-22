// Package pseudonymize replaces identifiers (ARNs, Kubernetes identities,
// account IDs) by stable tokens before evidence leaves the machine
// (--llm-redact-identifiers, DESIGN.md §10), and puts them back in what
// comes back. The mapping lives only in memory, in the process that made
// it.
package pseudonymize

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Mapping is one reversible replacement of identifiers by tokens.
type Mapping struct {
	forward map[string]string
	reverse map[string]string
	counts  map[string]int
}

// New returns an empty mapping.
func New() *Mapping {
	return &Mapping{forward: map[string]string{}, reverse: map[string]string{}, counts: map[string]int{}}
}

// Identifier kinds, longest first: an ARN or a Kubernetes identity holds
// an account ID, which then goes with it.
var kinds = []struct {
	name string
	re   *regexp.Regexp
}{
	{"k8s", regexp.MustCompile(`k8s:[^\s"'<>,;)\]]+`)},
	{"arn", regexp.MustCompile(`arn:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9-]*:\d{0,12}:[^\s"'<>,;)\]]+`)},
	{"account", regexp.MustCompile(`\b\d{12}\b`)},
}

// token: a fixed-width name, so that no token is a prefix of another
// (arn-0001 and arn-0010).
func (m *Mapping) token(kind, id string) string {
	if t, ok := m.forward[id]; ok {
		return t
	}
	m.counts[kind]++
	t := fmt.Sprintf("%s-%04d", kind, m.counts[kind])
	m.forward[id], m.reverse[t] = t, id
	return t
}

// Apply replaces every identifier in s by its token.
func (m *Mapping) Apply(s string) string {
	for _, k := range kinds {
		s = k.re.ReplaceAllStringFunc(s, func(id string) string {
			if _, isToken := m.reverse[id]; isToken {
				return id
			}
			return m.token(k.name, id)
		})
	}
	return s
}

// Restore puts the identifiers back in s.
func (m *Mapping) Restore(s string) string {
	tokens := make([]string, 0, len(m.reverse))
	for t := range m.reverse {
		tokens = append(tokens, t)
	}
	sort.Strings(tokens)
	pairs := make([]string, 0, 2*len(tokens))
	for _, t := range tokens {
		pairs = append(pairs, t, m.reverse[t])
	}
	return strings.NewReplacer(pairs...).Replace(s)
}

// Len is the number of identifiers mapped.
func (m *Mapping) Len() int { return len(m.forward) }
