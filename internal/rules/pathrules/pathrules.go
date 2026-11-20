// Package pathrules holds the cross-layer path rules (DESIGN.md §8.1):
// an entry reaches the plaintext of a crown jewel.
package pathrules

import (
	"cmp"
	"slices"

	"github.com/r3oof-900/clapa/internal/access"
	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/paths"
	"github.com/r3oof-900/clapa/internal/rules"
	"github.com/r3oof-900/clapa/internal/scoring"
)

// Rule IDs.
const (
	WorkloadReadsJewel = "CLAPA-PATH-001"
	EscalationToJewel  = "CLAPA-PATH-002"
	PublicJewel        = "CLAPA-PATH-003"
)

type pathRule struct{ meta rules.Meta }

func (r *pathRule) Meta() rules.Meta { return r.meta }

// Rules returns the three path rules.
func Rules() []rules.Rule {
	ref := func(t, u string) rules.Reference { return rules.Reference{Title: t, URL: u} }
	s3enc := ref("Amazon S3 › Protecting data with server-side encryption", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html")
	return []rules.Rule{
		&pathRule{rules.Meta{
			ID: WorkloadReadsJewel, Version: "1.0.0", Kind: rules.KindPath,
			Title:      "A workload can read crown-jewel data",
			Rationale:  "An entry workload reaches the plaintext of classified data through its identity (IRSA, Pod Identity, role chaining, node role): a compromise of the workload is a compromise of the data.",
			Techniques: []string{"T1078.004", "T1530"},
			References: []rules.Reference{ref("EKS › IAM roles for service accounts", "https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html"), s3enc},
			Failing:    []string{"01_classic/vulnerable", "06_role_chain_cross_account/vulnerable", "09_hostnetwork_imds/vulnerable"},
			Passing:    []string{"01_classic/fixed", "02_ec_scoped_to_legit_bucket/vulnerable", "11_boundary_deny/vulnerable"},
		}},
		&pathRule{rules.Meta{
			ID: EscalationToJewel, Version: "1.0.0", Kind: rules.KindPath,
			Title:      "Privilege escalation leads to crown-jewel data",
			Rationale:  "The path to the data uses an escalation primitive (iam:PassRole into compute, Kubernetes pod creation as another service account): permissions that look harmless on their own reach the data.",
			Techniques: []string{"T1098", "T1548", "T1610", "T1530"},
			References: []rules.Reference{ref("IAM › Granting a user permissions to pass a role", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html"), ref("Kubernetes › RBAC good practices (escalation)", "https://kubernetes.io/docs/concepts/security/rbac-good-practices/")},
			Failing:    []string{"07_passrole_lambda/vulnerable", "08_rbac_create_pods/vulnerable"},
			Passing:    []string{"07_passrole_lambda/fixed", "08_rbac_create_pods/fixed"},
		}},
		&pathRule{rules.Meta{
			ID: PublicJewel, Version: "1.0.0", Kind: rules.KindPath,
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
	perEntry := map[graph.NodeID]int{}
	for i := range in.Pairs {
		perEntry[in.Pairs[i].Entry]++
	}
	var out []rules.Finding
	for i := range in.Pairs {
		p := &in.Pairs[i]
		if len(p.Paths) == 0 {
			continue
		}
		f := build(in, p, perEntry[p.Entry])
		if classify(in.Graph, p.Entry, f.PathEdges) == r.meta.ID {
			out = append(out, f)
		}
	}
	return out
}

func classify(g *graph.Graph, entry graph.NodeID, path []graph.EdgeID) string {
	if g.Node(entry).ID == access.AnonymousID() {
		return PublicJewel
	}
	for _, id := range path {
		if g.Edge(id).Kind == graph.CanEscalate {
			return EscalationToJewel
		}
	}
	return WorkloadReadsJewel
}

// build turns a pair into a finding: its representative path is the one
// with the highest score (ties: fewer edges, then the first in order).
func build(in *rules.Input, p *paths.Pair, jewels int) rules.Finding {
	g := in.Graph
	jewel := in.Jewels[p.Jewel]
	class, _ := jewel.Classification()
	exposure := in.Entries[p.Entry].Exposure
	best, bestFactors := p.Paths[0], scoring.Path(g, p.Paths[0], exposure, scoring.Classification(class), jewels)
	for _, path := range p.Paths[1:] {
		f := scoring.Path(g, path, exposure, scoring.Classification(class), jewels)
		if f.Score > bestFactors.Score || (f.Score == bestFactors.Score && len(path) < len(best)) {
			best, bestFactors = path, f
		}
	}
	f := rules.Finding{
		Entry: g.Node(p.Entry).Identity, Jewel: g.Node(p.Jewel).Identity,
		EntryID: g.Node(p.Entry).ID, JewelID: g.Node(p.Jewel).ID,
		PathEdges: best, Paths: len(p.Paths), Truncated: p.Truncated, Factors: bestFactors, Confirmed: true,
		Location: rules.SourceOf(in.Inventory, g.Node(p.Entry).ID),
	}
	if f.Location.IsZero() {
		f.Location = *jewel.Source()
	}
	describePath(g, best, &f)
	chokepoints(g, p, &f)
	slices.SortFunc(f.ChokepointEdge, cmp.Compare)
	return f
}

// describePath fills the path text, confirmation, confidence, defaults and
// evidence of the representative path.
func describePath(g *graph.Graph, best paths.Path, f *rules.Finding) {
	conf := graph.High
	defaults := map[string]bool{}
	for _, id := range best {
		e := g.Edge(id)
		f.Path = append(f.Path, string(e.Kind)+" "+g.Node(e.To).Identity)
		conf = min(conf, e.Confidence)
		if e.Verdict != eval.Allow || (e.Precondition != nil && e.Precondition.State != model.True) {
			f.Confirmed = false
		}
		for _, u := range append([]graph.EdgeID{id}, e.Under...) {
			for _, d := range g.Edge(u).Defaults {
				defaults[d] = true
			}
			f.Evidence = append(f.Evidence, g.Edge(u).Evidence...)
		}
	}
	if !f.Confirmed {
		conf = graph.Low
	}
	f.Confidence = conf.String()
	for d := range defaults {
		f.DefaultsUsed = append(f.DefaultsUsed, d)
	}
	slices.Sort(f.DefaultsUsed)
}

// chokepoints fills the cheapest fix and its equal-cost alternatives.
func chokepoints(g *graph.Graph, p *paths.Pair, f *rules.Finding) {
	if !p.Cut.Finite {
		f.NoFix = true
		return
	}
	f.CutCost = p.Cut.Cost
	for _, e := range p.Cut.Edges {
		id := graph.EdgeID(e) //nolint:gosec // G115: edge indices of a graph bounded far below 2^31
		f.ChokepointEdge = append(f.ChokepointEdge, id)
		f.Chokepoints = append(f.Chokepoints, g.Describe(id))
	}
	for _, e := range p.Alternative {
		f.Alternative = append(f.Alternative, g.Describe(e))
	}
	slices.Sort(f.Chokepoints)
	slices.Sort(f.Alternative)
	slices.SortFunc(f.ChokepointEdge, cmp.Compare)
}
