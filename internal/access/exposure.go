package access

import (
	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/scoring"
)

// Internet is the canonical identity of the internet node.
const Internet = "internet"

// InternetID is the node ID of the internet: the source of EXPOSED_TO.
func InternetID() model.ID { return model.NewID(model.KindInternet, Internet) }

// exposures adds EXPOSED_TO from the internet to every workload behind a
// public or possibly public exposure (DESIGN.md §7.2): ALLOW for an
// internet-facing load balancer or Ingress, UNKNOWN for a NodePort (node
// security groups are not in manifests). A private exposure (an internal
// load balancer) is not reachable from the internet and has no edge. The fix
// removes the exposure (revoke, cost 20, SCORING.md §4.1): an internal
// scheme alone leaves the workload an entry of its own (an internal load
// balancer, exposure 500), so the same path would start there.
func (b *builder) exposures() {
	for _, x := range b.inv.Exposures {
		if x.Public() == model.False {
			continue
		}
		if _, ok := b.g.Lookup(x.Workload()); !ok {
			continue
		}
		verdict := eval.Allow
		if x.Public() == model.Unknown {
			verdict = eval.Unknown
		}
		src := x.Source()
		b.g.Node(InternetID(), model.KindInternet, Internet)
		b.edge(InternetID(), x.Workload(), graph.ExposedTo, x.Via(), &eval.Decision{Verdict: verdict}, func(e *graph.Edge) {
			e.Evidence = []string{x.Via() + " " + src.String()}
			e.Fixes = []graph.Fix{{
				Side: graph.SideExposure, Kind: graph.FixRevoke, Policy: x.Via() + " " + src.Address(),
				Cost: scoring.FixCost(graph.ExposedTo, x.Via(), graph.SideExposure, graph.FixRevoke),
			}}
		})
	}
}

// nodeRoleFixes: a pod without hostNetwork is cut off from IMDS by IMDSv2
// with a hop limit of 1 (node side, narrow, 3). A hostNetwork pod shares the
// node's network namespace, so neither the hop limit nor IMDSv2 stops it:
// only turning the node group's metadata endpoint off (node side) does, or
// removing hostNetwork (workload side) when the node already keeps other
// pods out; both remove something set on purpose (revoke, 5). SCORING.md
// §4.1 cites the sources: Kubernetes API › PodSpec › hostNetwork ("Use the
// host's network namespace"); EC2 User Guide › "Change the PUT response hop
// limit" and "Turn off access to instance metadata"; EKS Best Practices ›
// "Restrict access to the instance profile assigned to the worker node"
// (IMDSv2 and hop limit 1 for pods; it does not discuss hostNetwork, so
// that a hostNetwork pod is not stopped by the hop limit is our reasoning
// from the first two: it makes no extra network hop).
func nodeRoleFixes(w *model.Workload, ng *model.NodeGroup) []graph.Fix {
	label := "node group " + ng.Name
	if !w.HostNetwork() {
		return []graph.Fix{{
			Side: graph.SideNode, Kind: graph.FixNarrow, Policy: label + ": http_tokens = required, hop limit 1",
			Cost: scoring.FixCost(graph.NodeRole, "", graph.SideNode, graph.FixNarrow),
		}}
	}
	fixes := []graph.Fix{{
		Side: graph.SideNode, Kind: graph.FixRevoke, Policy: label + ": http_endpoint = disabled",
		Cost: scoring.FixCost(graph.NodeRole, "", graph.SideNode, graph.FixRevoke),
	}}
	// Removing hostNetwork is a fix only when the node already keeps other
	// pods out (IMDSv2 required, hop limit 1); otherwise the pod reaches
	// IMDS through the pod network too.
	if imdsReachable(false, ng) == model.False {
		fixes = append(fixes, graph.Fix{
			Side: graph.SideWorkload, Kind: graph.FixRevoke, Policy: w.Identity() + ": hostNetwork removed",
			Cost: scoring.FixCost(graph.NodeRole, "", graph.SideWorkload, graph.FixRevoke),
		})
	}
	return fixes
}
