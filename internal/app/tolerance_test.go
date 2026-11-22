package app

import (
	"testing"

	"github.com/r3oof-900/clapa/internal/collect/tfraw"
	"github.com/r3oof-900/clapa/internal/config"
	"github.com/r3oof-900/clapa/internal/coverage"
)

// Gaps count per kind beyond that kind's tolerance (default 0); a plan
// attribute the provider computes is not counted: no decision rests on it
// unless an edge does, and that edge carries its own UNKNOWN (DESIGN.md
// 4.6, 12.1).
func TestGapsOverTolerance(t *testing.T) {
	gaps := []coverage.Gap{
		{Kind: coverage.KindUnresolved, Detail: "var.x"},
		{Kind: coverage.KindUnresolved, Detail: "arn (" + tfraw.ReasonComputed + ")"},
		{Kind: coverage.KindUnresolved, Detail: "var.y"},
		{Kind: coverage.KindAccessDenied, Detail: "kms:GetKeyPolicy"},
	}
	for name, c := range map[string]struct {
		tolerance map[string]int
		want      int
	}{
		"default":         {nil, 3},
		"unresolved 1":    {map[string]int{"unresolved": 1}, 2},
		"unresolved 5":    {map[string]int{"unresolved": 5}, 1},
		"every kind":      {map[string]int{"unresolved": 2, "access-denied": 1}, 0},
		"other kind only": {map[string]int{"timeout": 9}, 3},
	} {
		cfg := &config.Config{}
		cfg.Coverage.Tolerance = c.tolerance
		if got := gapsOverTolerance(gaps, cfg); got != c.want {
			t.Errorf("%s: %d over tolerance, want %d", name, got, c.want)
		}
	}
}
