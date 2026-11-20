// Package findings finishes rule findings: fingerprints, suppressions,
// baseline comparison, ordering and the exit code (DESIGN.md §8, §11).
package findings

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/rules"
)

// Fingerprint = sha256(rule ID, rule major version, canonical IDs of entry
// and jewel) for a path finding; sha256(rule ID, major version, resource ID)
// for a posture finding (DESIGN.md §8). It names the problem, not its fix:
// the path, the cut and every cost and weight are left out, so re-pricing a
// fix or changing a weight never resets a suppression or a baseline. File
// lines are left out too, so moving code keeps suppressions.
func Fingerprint(rule, major string, entry, jewel model.ID) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{"clapa/fingerprint/v1", rule, major, string(entry), string(jewel)}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// PostureFingerprint fingerprints a posture finding.
func PostureFingerprint(rule, major string, resource model.ID) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{"clapa/fingerprint/v1", rule, major, string(resource)}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// Finish sets fingerprints and orders findings: severity, then score, then
// rule, entry, jewel, resource.
func Finish(fs []rules.Finding, reg *rules.Registry) []rules.Finding {
	out := slices.Clone(fs)
	for i := range out {
		f := &out[i]
		r, _ := reg.Get(f.Rule)
		m := r.Meta()
		if f.Kind == rules.KindPosture {
			f.Fingerprint = PostureFingerprint(f.Rule, m.Major(), f.ResourceID)
		} else {
			f.Fingerprint = Fingerprint(f.Rule, m.Major(), f.EntryID, f.JewelID)
		}
	}
	slices.SortStableFunc(out, func(a, b rules.Finding) int {
		return cmp.Or(cmp.Compare(b.Factors.Score, a.Factors.Score), cmp.Compare(a.Rule, b.Rule),
			cmp.Compare(a.Entry, b.Entry), cmp.Compare(a.Jewel, b.Jewel), cmp.Compare(a.Resource, b.Resource))
	})
	return out
}

// Suppression silences one finding until it expires (.clapa-ignore.yaml).
type Suppression struct {
	Fingerprint string
	Reason      string
	Owner       string
	Expires     time.Time
}

// Suppressed is a finding with the suppression that silenced it.
type Suppressed struct {
	Finding     rules.Finding
	Suppression Suppression
}

// Apply separates suppressed findings. An expired suppression does not
// apply: its finding fires again and the suppression is listed as expired.
func Apply(fs []rules.Finding, sups []Suppression, now time.Time) (active []rules.Finding, suppressed []Suppressed, expired []Suppression) {
	byFP := map[string]Suppression{}
	for _, s := range sups {
		if now.After(s.Expires) {
			expired = append(expired, s)
			continue
		}
		byFP[s.Fingerprint] = s
	}
	for i := range fs {
		if s, ok := byFP[fs[i].Fingerprint]; ok {
			suppressed = append(suppressed, Suppressed{Finding: fs[i], Suppression: s})
		} else {
			active = append(active, fs[i])
		}
	}
	return active, suppressed, expired
}

// Diff compares findings with a baseline's fingerprints: new findings and
// fingerprints that are resolved.
func Diff(fs []rules.Finding, baseline []string) (added []rules.Finding, resolved []string) {
	current := map[string]bool{}
	for i := range fs {
		current[fs[i].Fingerprint] = true
	}
	old := map[string]bool{}
	for _, b := range baseline {
		old[b] = true
		if !current[b] {
			resolved = append(resolved, b)
		}
	}
	for i := range fs {
		if !old[fs[i].Fingerprint] {
			added = append(added, fs[i])
		}
	}
	slices.Sort(resolved)
	return added, resolved
}

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4} //nolint:gochecknoglobals // constant table

// AtOrAbove reports whether severity is at or above threshold.
func AtOrAbove(severity, threshold string) bool {
	return severityRank[severity] >= severityRank[threshold]
}

// Exit codes (DESIGN.md §11).
const (
	ExitOK         = 0
	ExitFindings   = 1
	ExitUsage      = 2
	ExitIncomplete = 3
)

// ExitCode is 1 for any finding at or above failOn (unconfirmed ones count),
// else 3 when coverage gaps exceed tolerance or nothing was collected, else 0.
func ExitCode(fs []rules.Finding, failOn string, collected, gapsOverTolerance int) int {
	for i := range fs {
		if AtOrAbove(fs[i].Factors.Severity, failOn) {
			return ExitFindings
		}
	}
	if collected == 0 || gapsOverTolerance > 0 {
		return ExitIncomplete
	}
	return ExitOK
}

// Edges lists the descriptions of a finding's chokepoint edges in the graph
// (for reports that link edges).
func Edges(g *graph.Graph, ids []graph.EdgeID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = g.Describe(id)
	}
	return out
}
