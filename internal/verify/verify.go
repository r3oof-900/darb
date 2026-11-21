package verify

import (
	"fmt"
	"maps"
	"slices"

	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/remediate"
)

// Verification (DESIGN.md §9.2), on two levels, both required:
//
//  1. In memory: the plan's edits are applied to a copy of the canonical
//     model and the evaluator, access builder, path search and rules run
//     again. The targeted finding must be gone, every declared intended
//     access must stay as it was (a verified one stays verified), and no
//     finding may appear or rise in severity.
//  2. On files: the patch is applied to a copy of the inputs and the scan
//     runs from scratch (parse, normalize, evaluate). Its result must be the
//     in-memory result exactly: level 1 shows the model change is right,
//     level 2 that the patch is that change. Any difference rejects the fix.

// Result is what verification compares.
type Result struct {
	Findings map[string]string // fingerprint -> severity
	Intended map[string]string // "principal action resource" -> status
	ExitCode int
}

// Analyzer analyses an inventory (the scan after normalization).
type Analyzer func(*model.Inventory) (*Result, error)

// Outcome is a verification's verdict.
type Outcome struct {
	OK      bool
	Reasons []string // why the fix is rejected; empty when OK
	After   *Result
}

// statusRank: verified > unconfirmed > not-satisfied; not-modelled and
// unknown statuses only compare equal.
func statusRank(s string) int {
	switch s {
	case "verified":
		return 3
	case "unconfirmed":
		return 2
	case "not-satisfied":
		return 1
	}
	return 0
}

// InMemory verifies a plan against the model: before is the analysis of
// inv, target the fingerprint the plan must remove.
func InMemory(inv *model.Inventory, before *Result, plan *remediate.Plan, analyze Analyzer) Outcome {
	var edits []remediate.Edit
	for i := range plan.Changes {
		c := &plan.Changes[i]
		if c.TODO != "" {
			return Outcome{Reasons: []string{"not generated: " + c.TODO}}
		}
		edits = append(edits, c.Edits...)
	}
	if len(edits) == 0 {
		return Outcome{Reasons: []string{"the plan has no edit"}}
	}
	changed, err := remediate.Apply(inv, edits)
	if err != nil {
		return Outcome{Reasons: []string{err.Error()}}
	}
	after, err := analyze(changed)
	if err != nil {
		return Outcome{Reasons: []string{"analysis after the change: " + err.Error()}}
	}
	reasons := Compare(before, after, plan.Fingerprint)
	return Outcome{OK: len(reasons) == 0, Reasons: reasons, After: after}
}

// Compare lists why after is not an acceptable result of fixing target.
func Compare(before, after *Result, target string) []string {
	var out []string
	if _, still := after.Findings[target]; still {
		out = append(out, "the targeted finding "+target+" is still reported")
	}
	for _, fp := range slices.Sorted(maps.Keys(after.Findings)) {
		sev, was := before.Findings[fp]
		switch {
		case !was:
			out = append(out, fmt.Sprintf("a new finding appears: %s (%s)", fp, after.Findings[fp]))
		case severityRank(after.Findings[fp]) > severityRank(sev):
			out = append(out, fmt.Sprintf("finding %s rises from %s to %s", fp, sev, after.Findings[fp]))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(before.Intended)) {
		b, a := before.Intended[k], after.Intended[k]
		if a != b && (statusRank(a) < statusRank(b) || statusRank(b) == 0) {
			out = append(out, fmt.Sprintf("intended access %s goes from %s to %s", k, b, orNone(a)))
		}
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "missing"
	}
	return s
}

func severityRank(s string) int {
	return slices.Index([]string{"info", "low", "medium", "high", "critical"}, s)
}

// Same lists every difference between the in-memory and the on-file result
// (level 2): findings, severities, intended access and the exit code.
func Same(memory, files *Result) []string {
	var out []string
	for _, fp := range slices.Sorted(maps.Keys(memory.Findings)) {
		if files.Findings[fp] != memory.Findings[fp] {
			out = append(out, fmt.Sprintf("finding %s: %s in memory, %s after the patch", fp, memory.Findings[fp], orNone(files.Findings[fp])))
		}
	}
	for _, fp := range slices.Sorted(maps.Keys(files.Findings)) {
		if _, ok := memory.Findings[fp]; !ok {
			out = append(out, fmt.Sprintf("finding %s appears only after the patch (%s)", fp, files.Findings[fp]))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(memory.Intended)) {
		if files.Intended[k] != memory.Intended[k] {
			out = append(out, fmt.Sprintf("intended access %s: %s in memory, %s after the patch", k, memory.Intended[k], orNone(files.Intended[k])))
		}
	}
	if memory.ExitCode != files.ExitCode {
		out = append(out, fmt.Sprintf("exit code: %d in memory, %d after the patch", memory.ExitCode, files.ExitCode))
	}
	return out
}
