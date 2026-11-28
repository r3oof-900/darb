package app

import (
	"fmt"
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/access"
	"github.com/r3oof-900/darb/internal/config"
	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/paths"
	"github.com/r3oof-900/darb/pkg/schema"
)

// NoteIntendedOtherRoute is the subject of the note that names a declared
// intended access whose pair another route also reaches (DESIGN.md §9.1).
const NoteIntendedOtherRoute = "Intended access reached by another route"

// unbreakable prices an edge no change breaks when routes are compared.
const unbreakable int64 = 1 << 40

// intendedTargets resolves each intended_access resource to a bucket of the
// inventory ("arn:aws:s3:::B/*" names bucket B); nil when not modelled.
func intendedTargets(inv *model.Inventory, cfg *config.Config) []*model.Resource {
	out := make([]*model.Resource, len(cfg.IntendedAccess))
	for i, ia := range cfg.IntendedAccess {
		if ia.Action != "s3:GetObject" {
			continue
		}
		bucket, _, _ := strings.Cut(ia.Resource, "/")
		for _, r := range inv.Resources {
			if r.ARN() == bucket && r.Kind() == model.KindS3Bucket {
				out[i] = r
			}
		}
	}
	return out
}

// intendedRoutes: for each declared intended access, the one route the scan
// protects (DESIGN.md §9.1): the workload runs as its service account and
// every identity it then takes is its own (the role of its service
// account's IRSA annotation or Pod Identity association, and the role that
// association chains into), with no escalation, no node role and no
// mapping. Among several, a confirmed one first, then the cheapest by the
// real cut costs (the sum over its edges), then the fewest edges, then path
// order. nil when the access is not modelled or no such route exists:
// every route of the pair is then reported.
func intendedRoutes(g *graph.Graph, inv *model.Inventory, cfg *config.Config, targets []*model.Resource) []paths.Path {
	base := costs(g, cfg, nil)
	out := make([]paths.Path, len(cfg.IntendedAccess))
	for i, ia := range cfg.IntendedAccess {
		from, ok1 := g.Lookup(model.NewID(model.KindK8sWorkload, ia.Principal))
		if targets[i] == nil || !ok1 {
			continue
		}
		to, ok2 := g.Lookup(targets[i].ID())
		if !ok2 {
			continue
		}
		own := ownRoles(inv, g.Node(from).Identity)
		for _, p := range paths.Analyze(g, []graph.NodeID{from}, []graph.NodeID{to}, paths.Options{Cost: base}) {
			out[i] = bestRoute(g, base, p.Paths, own)
		}
	}
	return out
}

// bestRoute: among the paths that are own routes, a confirmed one first,
// then the cheapest, then the fewest edges, then the first.
func bestRoute(g *graph.Graph, base func(graph.EdgeID) int64, candidates []paths.Path, own map[string]bool) paths.Path {
	var best paths.Path
	var bestKey [3]int64
	for _, path := range candidates {
		if !ownRoute(g, path, own) {
			continue
		}
		key := [3]int64{1, routeCost(g, base, path), int64(len(path))}
		if confirmed(g, path) {
			key[0] = 0
		}
		if best == nil || slices.Compare(key[:], bestKey[:]) < 0 {
			best, bestKey = path, key
		}
	}
	return best
}

// ownRoles: the ARNs of the roles the workload's service account is bound
// to (its IRSA annotation, its Pod Identity associations and their target
// roles).
func ownRoles(inv *model.Inventory, workload string) map[string]bool {
	own := map[string]bool{}
	var w *model.Workload
	for _, x := range inv.Workloads {
		if x.Identity() == workload {
			w = x
		}
	}
	if w == nil {
		return own
	}
	for _, sa := range inv.ServiceAccounts {
		if sa.Cluster == w.Cluster() && sa.Namespace == w.Namespace() && sa.Name == w.ServiceAccount() && sa.RoleARN != "" {
			own[sa.RoleARN] = true
		}
	}
	for _, a := range inv.PodIdentity {
		if a.Cluster == w.Cluster() && a.Namespace == w.Namespace() && a.ServiceAccount == w.ServiceAccount() {
			own[a.RoleARN] = true
			if a.TargetRoleARN != "" {
				own[a.TargetRoleARN] = true
			}
		}
	}
	return own
}

// ownRoute: the path starts with the workload's cloud identity (RUNS_AS)
// and every identity it takes afterwards is one of its own roles.
func ownRoute(g *graph.Graph, path paths.Path, own map[string]bool) bool {
	if len(path) == 0 {
		return false
	}
	if first := g.Edge(path[0]); first.Kind != graph.RunsAs || first.Sub != "" {
		return false
	}
	foreign := []graph.Kind{graph.CanEscalate, graph.NodeRole, graph.MapsTo, graph.RunsAs, graph.ExposedTo}
	for _, id := range path[1:] {
		e := g.Edge(id)
		if slices.Contains(foreign, e.Kind) || e.Kind == graph.Assumes && !own[g.Node(e.To).Identity] {
			return false
		}
	}
	return true
}

// routeCost: the sum of the real cut costs of a route's edges.
func routeCost(g *graph.Graph, base func(graph.EdgeID) int64, path paths.Path) int64 {
	var sum int64
	for _, id := range path {
		sum += edgeCost(g, base, id)
	}
	return sum
}

// edgeCost: an edge's cheapest side (a derived read: its cheaper
// underlying edge), unbreakable when no change breaks it.
func edgeCost(g *graph.Graph, base func(graph.EdgeID) int64, id graph.EdgeID) int64 {
	e := g.Edge(id)
	if e.Kind == graph.CanReadPlaintext && len(e.Under) > 0 {
		best := unbreakable
		for _, u := range e.Under {
			best = min(best, edgeCost(g, base, u))
		}
		return best
	}
	switch c := base(id); {
	case c == paths.Uncuttable:
		return unbreakable
	case c != paths.Default:
		return c
	}
	best := unbreakable
	for i := range e.Fixes {
		best = min(best, e.Fixes[i].Cost)
	}
	return best
}

// intendedEdges: every edge of a protected route is uncuttable, for every
// finding (SCORING.md §4), and so are the edges a derived edge on it stands
// for.
func intendedEdges(g *graph.Graph, routes []paths.Path) map[graph.EdgeID]bool {
	out := map[graph.EdgeID]bool{}
	for _, route := range routes {
		for _, id := range route {
			out[id] = true
			for _, u := range g.Edge(id).Under {
				out[u] = true
			}
		}
	}
	return out
}

// withoutIntended: a pair a declared intended access names (the workload
// reading the whole bucket, resource "<bucket ARN>/*") loses its protected
// route, which is what the user said the workload does, whatever the
// bucket's classification; its cut may not break that route. Any other
// route of the pair stays a finding, and a note names the pair; with no
// other route the pair is not reported. A declaration of part of a bucket
// (a prefix) leaves the pair as it is: the path reads more than declared.
func withoutIntended(pairs []paths.Pair, g *graph.Graph, cfg *config.Config, targets []*model.Resource, routes []paths.Path) ([]paths.Pair, []access.Note) {
	declared := map[[2]graph.NodeID]int{}
	for i, ia := range cfg.IntendedAccess {
		if targets[i] == nil || ia.Resource != targets[i].ARN()+"/*" {
			continue
		}
		from, ok1 := g.Lookup(model.NewID(model.KindK8sWorkload, ia.Principal))
		to, ok2 := g.Lookup(targets[i].ID())
		if ok1 && ok2 {
			declared[[2]graph.NodeID{from, to}] = i
		}
	}
	var notes []access.Note
	out := pairs[:0]
	for _, p := range pairs {
		i, ok := declared[[2]graph.NodeID{p.Entry, p.Jewel}]
		if !ok {
			out = append(out, p)
			continue
		}
		route := routes[i]
		p.Protected = route
		p.Paths = slices.DeleteFunc(slices.Clone(p.Paths), func(path paths.Path) bool { return declaredRoute(g, path, route) })
		if len(p.Paths) == 0 && !p.Truncated {
			continue
		}
		notes = append(notes, otherRouteNote(&cfg.IntendedAccess[i], routes[i] != nil, len(p.Paths)))
		out = append(out, p)
	}
	return out, notes
}

// declaredRoute: the path is the protected route, or follows it and then
// escalates from an identity on it: that identity already reads the target
// as declared, so the escalation adds nothing for this pair (it is
// dominated, DESIGN.md §8; other jewels still see it).
func declaredRoute(g *graph.Graph, path, route paths.Path) bool {
	sel := paths.Select{Protected: route}
	if sel.OnRoute(path) {
		return true
	}
	k := slices.IndexFunc(path, func(id graph.EdgeID) bool { return g.Edge(id).Kind == graph.CanEscalate })
	return k > 0 && k < len(route) && slices.Equal(path[:k], route[:k])
}

func otherRouteNote(ia *config.IntendedAccess, ownRoute bool, others int) access.Note {
	routes := "1 other route reaches"
	if others != 1 {
		routes = fmt.Sprintf("%d other routes reach", others)
	}
	detail := fmt.Sprintf("%s reads %s as declared, through its own identity; %s it too and is reported: only the declared route is kept",
		ia.Principal, ia.Resource, routes)
	if others != 1 {
		detail = strings.Replace(detail, "and is reported", "and are reported", 1)
	}
	if !ownRoute {
		detail = fmt.Sprintf("%s reaches %s, but not through its own identity (the role of its service account): every route is reported",
			ia.Principal, ia.Resource)
	}
	return access.Note{Kind: schema.NoteIntendedOtherRoute, Subject: NoteIntendedOtherRoute, Detail: detail}
}

// verifyIntended: each declared access is verified by its protected route:
// "verified" when that route is confirmed, "unconfirmed" when it rests on
// an UNKNOWN, "not-satisfied" when the workload's own identity does not
// reach the target (another route may: it is reported, not counted).
func verifyIntended(g *graph.Graph, cfg *config.Config, targets []*model.Resource, routes []paths.Path) []IntendedResult {
	out := []IntendedResult{}
	for i, ia := range cfg.IntendedAccess {
		r := IntendedResult{Principal: ia.Principal, Action: ia.Action, Resource: ia.Resource, Status: "not-satisfied"}
		_, ok := g.Lookup(model.NewID(model.KindK8sWorkload, ia.Principal))
		switch {
		case targets[i] == nil:
			r.Status, r.Detail = "not-modelled", "only s3:GetObject on a bucket in the input is verified"
		case !ok:
			r.Detail = "the principal is not a workload in the input"
		case routes[i] == nil:
			r.Detail = "no route through the workload's own identity (its service account's role) reaches the resource"
		case confirmed(g, routes[i]):
			r.Status = "verified"
		default:
			r.Status = "unconfirmed"
		}
		out = append(out, r)
	}
	return out
}

func confirmed(g *graph.Graph, path paths.Path) bool {
	for _, id := range path {
		e := g.Edge(id)
		if e.Verdict != eval.Allow || (e.Precondition != nil && e.Precondition.State != model.True) {
			return false
		}
	}
	return true
}
