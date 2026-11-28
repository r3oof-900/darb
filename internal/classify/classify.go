package classify

import (
	"cmp"
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/model"
)

// Rules decide what is a crown jewel (docs/DESIGN.md section 5).
type Rules struct {
	TagKeys   []string          // e.g. DataClass (case-insensitive)
	TagValues []string          // e.g. pii, pci, phi, secret (case-insensitive)
	Explicit  map[string]string // ARN (or K8s identity) -> classification
	// IgnoreUnclassified: a data store no rule classifies is no jewel
	// (crown_jewels.unclassified: ignore); by default it is one, of
	// classification Unclassified.
	IgnoreUnclassified bool
}

// Unclassified is the classification of a data store that no rule
// classifies (SCORING.md §1.2): a crown jewel all the same, since a store
// nobody tagged may hold anything; the report names each one.
const Unclassified = model.ClassUnclassified

// ByDefault is the rule that marks a store Unclassified.
const ByDefault = "default:unclassified"

// DataStore says whether a resource holds data and becomes an Unclassified
// jewel when nothing classifies it: an S3 bucket, a Secrets Manager secret,
// an SSM parameter that is a SecureString (or whose type is unknown: the
// worst case), a Kubernetes Secret. A KMS key protects data and holds none:
// it is a jewel only when classified.
func DataStore(r *model.Resource) bool {
	if r.Kind() == model.KindSSMParameter {
		return r.Encryption().Type != "none"
	}
	return r.Kind() == model.KindS3Bucket || r.Kind() == model.KindSecret || r.Kind() == model.KindK8sSecret
}

// jewelKinds are the kinds that hold data.
func jewelKind(k model.NodeKind) bool {
	return k == model.KindS3Bucket || k == model.KindSecret || k == model.KindSSMParameter ||
		k == model.KindK8sSecret || k == model.KindKMSKey
}

// CrownJewels returns the resources with their classification applied:
// explicit configuration first, then data-classification tags, then the
// default heuristic (a data resource tagged "sensitive"). Each records which
// rule marked it.
func CrownJewels(resources []*model.Resource, rules *Rules) []*model.Resource {
	out := make([]*model.Resource, 0, len(resources))
	for _, r := range resources {
		class, by := classifyOne(r, rules)
		if class != "" {
			r = r.WithClassification(class, by)
		}
		out = append(out, r)
	}
	return out
}

func classifyOne(r *model.Resource, rules *Rules) (class, by string) {
	if c, ok := rules.Explicit[r.ARN()]; ok {
		return c, "config:crown_jewels.explicit"
	}
	if !jewelKind(r.Kind()) {
		return "", ""
	}
	for _, t := range r.Tags() {
		if containsFold(rules.TagKeys, t.Key) && containsFold(rules.TagValues, t.Value) {
			return strings.ToLower(t.Value), "tag:" + t.Key
		}
	}
	for _, t := range r.Tags() {
		if strings.EqualFold(t.Value, "sensitive") || (strings.EqualFold(t.Key, "sensitive") && strings.EqualFold(t.Value, "true")) {
			return "sensitive", "heuristic:tagged-sensitive"
		}
	}
	if !rules.IgnoreUnclassified && DataStore(r) {
		return Unclassified, ByDefault
	}
	return "", ""
}

func containsFold(list []string, s string) bool {
	return slices.ContainsFunc(list, func(x string) bool { return strings.EqualFold(x, s) })
}

// EntryPoint is a workload an attacker can start from.
type EntryPoint struct {
	Workload model.ID  // the entry node: a workload, or an IAM user or root (credential-leak)
	Reason   string    // "exposed:Service/LoadBalancer", "assume-compromised", "credential-leak"
	Public   model.Tri // for exposures; Unknown for assume-compromised
	// Unknown: what is undecided about the entry itself (a user whose
	// credential state is not in the input); "" when nothing is.
	Unknown string
}

// CredentialLeak is the entry reason of an IAM user (or the root) with an
// active access key, or whose keys are not in the input (item 4).
const CredentialLeak = "credential-leak" //nolint:gosec // G101: an entry reason, not a credential.

// EntryPoints returns every exposed workload, plus every workload when the
// "assume any pod compromised" threat model is on (the default).
func EntryPoints(inv *model.Inventory, assumeCompromised bool) []EntryPoint {
	var out []EntryPoint
	exposed := map[model.ID]bool{}
	for _, e := range inv.Exposures {
		out = append(out, EntryPoint{Workload: e.Workload(), Reason: "exposed:" + e.Via(), Public: e.Public()})
		exposed[e.Workload()] = true
	}
	if assumeCompromised {
		for _, w := range inv.Workloads {
			if !exposed[w.ID()] {
				out = append(out, EntryPoint{Workload: w.ID(), Reason: "assume-compromised", Public: model.Unknown})
			}
		}
	}
	out = append(out, credentialEntries(inv)...)
	slices.SortFunc(out, func(a, b EntryPoint) int {
		return cmp.Or(strings.Compare(string(a.Workload), string(b.Workload)), strings.Compare(a.Reason, b.Reason))
	})
	return slices.Compact(out)
}

// credentialEntries: every IAM user, and the root, with an active access
// key; a user whose keys are not in the input is an entry too, at the same
// exposure, unconfirmed (DESIGN.md §5, item 4). An inactive key, or none,
// is no entry.
func credentialEntries(inv *model.Inventory) []EntryPoint {
	var out []EntryPoint
	for _, c := range inv.Credentials {
		if a := c.ActiveKey(); a == model.True {
			out = append(out, EntryPoint{Workload: c.Principal, Reason: CredentialLeak, Public: model.True})
		} else if a == model.Unknown {
			out = append(out, EntryPoint{
				Workload: c.Principal, Reason: CredentialLeak, Public: model.Unknown,
				Unknown: "credential state of the user is unknown: iam:GetCredentialReport and iam:ListAccessKeys are not in the input",
			})
		}
	}
	return out
}
