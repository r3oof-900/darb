// Package pathrules holds the cross-layer path rules (DESIGN.md §8.1):
// an entry reaches the plaintext of a crown jewel.
package pathrules

import (
	"slices"

	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/paths"
	"github.com/r3oof-900/darb/internal/rules"
)

// Rule IDs.
const (
	WorkloadReadsJewel = "DARB-PATH-001"
	EscalationToJewel  = "DARB-PATH-002"
	PublicJewel        = "DARB-PATH-003"
)

type pathRule struct{ meta rules.Meta }

func (r *pathRule) Meta() rules.Meta { return r.meta }

// Rules returns the three path rules.
func Rules() []rules.Rule {
	ref := func(t, u string) rules.Reference { return rules.Reference{Title: t, URL: u} }
	s3enc := ref("Amazon S3 › Protecting data with server-side encryption", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html")
	return []rules.Rule{
		&pathRule{rules.Meta{
			ID: WorkloadReadsJewel, Version: "1.1.0", Kind: rules.KindPath,
			Title:      "A workload can read crown-jewel data",
			Rationale:  "An entry workload reaches the plaintext of classified data, or of a data store nobody classified, through its identity (IRSA, Pod Identity, role chaining, node role): a compromise of the workload is a compromise of the data.",
			Techniques: []string{"T1078.004", "T1530"},
			References: []rules.Reference{ref("EKS › IAM roles for service accounts", "https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html"), s3enc},
			Failing:    []string{"01_classic/vulnerable", "06_role_chain_cross_account/vulnerable", "09_hostnetwork_imds/vulnerable", "24_unclassified_bucket/vulnerable"},
			Passing:    []string{"02a_ec_bucket_key/vulnerable", "02c_ec_mismatch/vulnerable", "11_boundary_deny/vulnerable", "24_unclassified_bucket/fixed"},
		}},
		&pathRule{rules.Meta{
			ID: EscalationToJewel, Version: "1.1.0", Kind: rules.KindPath,
			Title:      "Privilege escalation leads to crown-jewel data",
			Rationale:  "The path to the data uses an escalation primitive (iam:PassRole into compute, Kubernetes pod creation as another service account): permissions that look harmless on their own reach the data.",
			Techniques: []string{"T1098", "T1548", "T1610", "T1530"},
			References: []rules.Reference{ref("IAM › Granting a user permissions to pass a role", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html"), ref("Kubernetes › RBAC good practices (escalation)", "https://kubernetes.io/docs/concepts/security/rbac-good-practices/")},
			Failing:    []string{"07_passrole_lambda/vulnerable", "08_rbac_create_pods/vulnerable"},
			Passing:    []string{"07_passrole_lambda/fixed", "08_rbac_create_pods/fixed"},
		}},
		&pathRule{rules.Meta{
			ID: PublicJewel, Version: "1.1.0", Kind: rules.KindPath,
			Title:      "Crown-jewel data is publicly readable",
			Rationale:  "A resource policy grants a public principal read access and Block Public Access does not stop it: anyone on the internet reads the data.",
			Techniques: []string{"T1530"},
			References: []rules.Reference{ref("Amazon S3 › Blocking public access", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html")},
			Failing:    []string{"12_public_bucket/vulnerable"},
			Passing:    []string{"12_public_bucket/fixed"},
		}},
	}
}

func (r *pathRule) Evaluate(in *rules.Input) []rules.Finding {
	var out []rules.Finding
	all := analyze(in)
	for i := range all {
		if all[i].Rule == r.meta.ID {
			out = append(out, all[i])
		}
	}
	return out
}

// describePath fills the path text, confirmation, confidence, defaults and
// evidence of the representative path.
func describePath(g *graph.Graph, best paths.Path, f *rules.Finding, entry rules.Entry) {
	conf := graph.High
	defaults := map[string]bool{}
	f.Status = rules.StatusConfirmed
	for _, id := range best {
		e := g.Edge(id)
		f.Path = append(f.Path, graph.Label(e)+" "+g.Node(e.To).Identity)
		conf = min(conf, e.Confidence)
		f.Status = rules.Weaker(f.Status, edgeStatus(g, id))
		for _, u := range append([]graph.EdgeID{id}, e.Under...) {
			for _, d := range g.Edge(u).Defaults {
				defaults[d] = true
			}
			f.Evidence = append(f.Evidence, g.Edge(u).Evidence...)
		}
	}
	if entry.Unknown != "" {
		f.Status = rules.Weaker(f.Status, rules.StatusUnconfirmed)
	}
	f.Confirmed = f.Status == rules.StatusConfirmed
	switch f.Status {
	case rules.StatusConfirmedUnlessDenied:
		conf = graph.Medium
	case rules.StatusUnconfirmed:
		conf = graph.Low
	}
	if !f.Confirmed {
		f.Undecided = g.Undecided(best)
		if entry.Unknown != "" {
			f.Undecided = append(f.Undecided, entry.Unknown)
		}
	}
	f.Confidence = conf.String()
	for d := range defaults {
		f.DefaultsUsed = append(f.DefaultsUsed, d)
	}
	slices.Sort(f.DefaultsUsed)
}

// edgeStatus: what an edge leaves undecided (DESIGN.md 6.2). A derived
// edge takes its underlying edges'; an UNKNOWN precondition or an UNKNOWN
// that needs an unknown allow is unconfirmed; a deny-only UNKNOWN is
// confirmed unless denied.
func edgeStatus(g *graph.Graph, id graph.EdgeID) string {
	e := g.Edge(id)
	s := rules.StatusConfirmed
	if e.Precondition != nil && e.Precondition.State != model.True {
		s = rules.StatusUnconfirmed
	}
	if len(e.Under) > 0 {
		for _, u := range e.Under {
			s = rules.Weaker(s, edgeStatus(g, u))
		}
		return s
	}
	switch {
	case e.Verdict == eval.Allow:
	case e.DenyOnly:
		s = rules.Weaker(s, rules.StatusConfirmedUnlessDenied)
	default:
		s = rules.StatusUnconfirmed
	}
	return s
}
