package access

import (
	"strconv"
	"strings"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/eval/condition"
	"github.com/r3oof-900/clapa/internal/eval/match"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
)

// Options configure the access builder.
type Options struct {
	Partition string
	// Jewels are the crown jewels (classified resources).
	Jewels []*model.Resource
	// Assume holds context-key assumptions from clapa.yaml (e.g.
	// aws:PrincipalOrgID) for principals in the input.
	Assume map[string][]string
}

// Note is a coverage note about something the graph could not analyse.
type Note struct {
	Kind    string // e.g. "protected-data-outside-input"
	Subject string
	Detail  string
}

// Result is the access graph and its notes.
type Result struct {
	Graph *graph.Graph
	Notes []Note
}

// Anonymous is the canonical identity of the anonymous principal.
const Anonymous = "anonymous"

// AnonymousID is the node ID of the anonymous principal.
func AnonymousID() model.ID { return model.NewID(model.KindAnonymous, Anonymous) }

type builder struct {
	inv        *model.Inventory
	opts       *Options
	g          *graph.Builder
	policies   map[model.ID][]*model.PolicyDocument
	boundaries map[model.ID]*model.PolicyDocument
	trusts     map[model.ID]*model.PolicyDocument
	roles      []*model.Principal
	byARN      map[string]*model.Principal
	resources  map[string]*model.Resource
	clusters   map[string]*model.Cluster
	accounts   map[string][]*model.ServiceAccount // cluster/namespace -> service accounts
	workloads  map[string][]*model.Workload       // cluster/namespace -> workloads
	// minters: service accounts another account controls through RBAC;
	// selfMinters: accounts whose own RBAC lets them control themselves.
	minters     map[model.ID]bool
	selfMinters map[model.ID]eval.Verdict
	notes       []Note
}

// Build derives the access graph from the inventory (DESIGN.md §7.2): each
// edge is a decision of the evaluator, kept when it is ALLOW or UNKNOWN.
func Build(inv *model.Inventory, opts *Options) *Result {
	if opts.Partition == "" {
		opts.Partition = "aws"
	}
	b := &builder{
		inv: inv, opts: opts, g: graph.NewBuilder(),
		policies: map[model.ID][]*model.PolicyDocument{}, boundaries: map[model.ID]*model.PolicyDocument{},
		trusts: map[model.ID]*model.PolicyDocument{}, byARN: map[string]*model.Principal{},
		resources: map[string]*model.Resource{}, clusters: map[string]*model.Cluster{},
		accounts: map[string][]*model.ServiceAccount{}, workloads: map[string][]*model.Workload{},
		minters: map[model.ID]bool{}, selfMinters: map[model.ID]eval.Verdict{},
	}
	b.index()
	b.kubernetes()
	b.mappings()
	b.minted()
	b.identities()
	b.nodeRoles()
	b.reads()
	return &Result{Graph: b.g.Build(), Notes: b.notes}
}

func (b *builder) index() {
	for _, p := range b.inv.Policies {
		b.policies[p.Target] = append(b.policies[p.Target], p.Doc)
	}
	for _, p := range b.inv.Boundaries {
		b.boundaries[p.Target] = p.Doc
	}
	for _, t := range b.inv.Trusts {
		b.trusts[t.Role()] = t.Policy()
	}
	for _, p := range b.inv.Principals {
		b.g.Node(p.ID(), p.Kind(), p.Identity())
		b.byARN[p.Identity()] = p
		if p.Kind() == model.KindIAMRole {
			b.roles = append(b.roles, p)
		}
	}
	for _, r := range b.inv.Resources {
		b.resources[r.ARN()] = r
	}
	for _, c := range b.inv.Clusters {
		b.clusters[c.Name] = c
	}
	for _, sa := range b.inv.ServiceAccounts {
		b.g.Node(sa.ID, model.KindK8sServiceAcct, saIdentity(sa.Cluster, sa.Namespace, sa.Name))
		b.accounts[sa.Cluster+"/"+sa.Namespace] = append(b.accounts[sa.Cluster+"/"+sa.Namespace], sa)
	}
	for _, w := range b.inv.Workloads {
		b.g.Node(w.ID(), model.KindK8sWorkload, w.Identity())
		b.workloads[w.Cluster()+"/"+w.Namespace()] = append(b.workloads[w.Cluster()+"/"+w.Namespace()], w)
	}
}

func saIdentity(cluster, ns, name string) string {
	return model.K8sIdentity(cluster, ns, "ServiceAccount", name)
}

func saID(cluster, ns, name string) model.ID {
	return model.NewID(model.KindK8sServiceAcct, saIdentity(cluster, ns, name))
}

func (b *builder) node(id model.ID) graph.NodeID {
	n, _ := b.g.Lookup(id)
	return n
}

// edge adds an edge for an ALLOW or UNKNOWN decision.
func (b *builder) edge(from, to model.ID, kind graph.Kind, sub string, d *eval.Decision, extra func(*graph.Edge)) graph.EdgeID {
	e := &graph.Edge{
		From: b.node(from), To: b.node(to), Kind: kind, Sub: sub, For: graph.NoNode,
		Verdict: d.Verdict, Confidence: graph.High, Evidence: evidence(d),
	}
	if d.Verdict == eval.Unknown {
		e.Confidence = graph.Low
	}
	if extra != nil {
		extra(e)
	}
	return b.g.Edge(e)
}

func grants(v eval.Verdict) bool { return v == eval.Allow || v == eval.Unknown }

func evidence(d *eval.Decision) []string {
	var out []string
	for i := range d.Contributing {
		s := &d.Contributing[i]
		label := s.Sid
		if label == "" {
			label = "#" + strconv.Itoa(s.Index)
		}
		out = append(out, s.Effect.String()+" "+s.PolicyID+" "+label)
	}
	return out
}

// session is the request principal of a role session.
func (b *builder) session(role *model.Principal) match.RequestPrincipal {
	name := role.Identity()[strings.LastIndex(role.Identity(), "/")+1:]
	return match.RequestPrincipal{
		Kind: match.KindAssumedRole, Account: role.Account(), SourceARN: role.Identity(),
		ARN: "arn:" + b.opts.Partition + ":sts::" + role.Account() + ":assumed-role/" + name + "/clapa",
	}
}

// context is the request context of a role session: the principal keys
// AWS sets, the configured assumptions, and the extra keys given; every
// other key is unknown.
func (b *builder) context(role *model.Principal, present map[string][]string) *condition.Context {
	in := &condition.Input{Default: condition.StateUnknown, Present: map[string][]string{}}
	for k, v := range b.opts.Assume {
		in.Present[k] = v
	}
	if role != nil {
		in.Present["aws:PrincipalArn"] = []string{role.Identity()}
		in.Present["aws:PrincipalAccount"] = []string{role.Account()}
	}
	for k, v := range present {
		in.Present[k] = v
	}
	return condition.NewContext(in)
}

func (b *builder) identitySet(p *model.Principal, resource []*model.PolicyDocument, required bool) *eval.PolicySet {
	return &eval.PolicySet{
		Identity: b.policies[p.ID()], Boundary: b.boundaries[p.ID()],
		Resource: resource, ResourcePolicyRequired: required,
	}
}
