package app

import (
	"context"

	"github.com/r3oof-900/darb/internal/rules"
	"github.com/r3oof-900/darb/pkg/schema"
)

// AttachFixes remediates every path finding of the report (scan --fixes):
// the same plans, patches and two-level verification as darb remediate
// (DESIGN.md §9), attached to the finding in output order.
func AttachFixes(ctx context.Context, in *Inputs, l *Loaded, a *Analysis, r *schema.Report) error {
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.Kind != rules.KindPath {
			continue
		}
		rem, err := Remediate(ctx, in, l, a, f.Fingerprint)
		if err != nil {
			return err
		}
		f.Remediation = remediationOf(rem)
	}
	return nil
}

// remediationOf is a remediation as the report states it.
func remediationOf(r *Remediation) *schema.Remediation {
	out := &schema.Remediation{Fixes: []schema.Fix{}, Note: r.Note, Pending: r.Plan.Pending, Missing: r.Plan.Missing, NoFix: r.Plan.NoFix}
	for _, fix := range append([]*Remediation{r}, r.Others...) {
		if fix.Plan.Strategy == "" {
			continue // resolve steps only, an unconfirmed path, or no fix: nothing to apply
		}
		sf := schema.Fix{
			Strategy: fix.Plan.Strategy, Suggestion: fix.Plan.Suggestion, Changes: []schema.Change{},
			VerifiedInMemory: fix.Memory.OK, VerifiedOnFiles: fix.Files.OK, Pending: fix.Memory.Pending,
		}
		switch {
		case !fix.Memory.OK:
			sf.Reasons = fix.Memory.Reasons
		case !fix.Files.OK:
			sf.Reasons = fix.Files.Reasons
		}
		for i := range fix.Plan.Changes {
			c := &fix.Plan.Changes[i]
			sf.Changes = append(sf.Changes, schema.Change{Edge: c.Edge, Side: c.Side, Kind: c.Kind, Cost: c.Cost, Why: c.Why, TODO: c.TODO})
		}
		if fix.Patch != nil {
			sf.Diff, sf.TODO = fix.Patch.Diff(), fix.Patch.TODO
			for _, p := range fix.Patch.Policies {
				sf.Policies = append(sf.Policies, schema.Policy{ID: p.ID, Note: p.Note, Document: p.Document})
			}
		}
		out.Fixes = append(out.Fixes, sf)
	}
	return out
}
