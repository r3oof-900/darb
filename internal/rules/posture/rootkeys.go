package posture

import (
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/rules"
	"github.com/r3oof-900/darb/internal/scoring"
)

// RootAccessKey is the rule ID of an active access key on the root user
// (item 4, after v0.1.0-rc.1).
const RootAccessKey = "DARB-POST-009"

func rootKeyRule() rules.Rule {
	return &rule{
		meta(RootAccessKey, "Root user has active access keys",
			"An access key of the root user can do anything in the account and no IAM policy restricts it; AWS recommends that the root user have none. The credential report shows an active key (access_key_N_active): delete it and use roles.",
			scoring.BaseCritical, []string{"T1078.004"},
			[]rules.Reference{ref("IAM › Root user best practices", "https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html")},
			[]string{"29_credential_leak/root_key"}, []string{"29_credential_leak/vulnerable"}),
		graph.High, rootKeys,
	}
}

func rootKeys(in *rules.Input) []hit {
	var out []hit
	for _, p := range in.Inventory.Principals {
		if p.Kind() != model.KindAccountRoot {
			continue
		}
		c := in.Inventory.CredentialsOf(p.ID())
		if c.ActiveKey() != model.True {
			continue
		}
		h := hit{resource: p.Identity(), id: p.ID(), location: *p.Source(), evidence: c.Evidence()}
		out = append(out, h)
	}
	return out
}
