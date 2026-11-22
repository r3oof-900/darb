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
	return "", ""
}

func containsFold(list []string, s string) bool {
	return slices.ContainsFunc(list, func(x string) bool { return strings.EqualFold(x, s) })
}

// EntryPoint is a workload an attacker can start from.
type EntryPoint struct {
	Workload model.ID
	Reason   string    // "exposed:Service/LoadBalancer", "assume-compromised"
	Public   model.Tri // for exposures; Unknown for assume-compromised
}

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
	slices.SortFunc(out, func(a, b EntryPoint) int {
		return cmp.Or(strings.Compare(string(a.Workload), string(b.Workload)), strings.Compare(a.Reason, b.Reason))
	})
	return slices.Compact(out)
}
