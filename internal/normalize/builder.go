package normalize

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/model"
)

// ErrDuplicate is returned when two definitions have the same canonical
// identity (docs/DESIGN.md section 5: never "keep first, drop second").
var ErrDuplicate = errors.New("normalize: duplicate definition")

// ErrUnregisteredPlaceholder is returned when the inventory contains an
// unresolved placeholder that no normalizer created through Placeholder.
// Input containing the reserved text is rejected earlier, with its file:line;
// this is the last line of defence, and it fails closed.
var ErrUnregisteredPlaceholder = errors.New("normalize: unresolved placeholder not created by a normalizer")

// Builder accumulates an Inventory and rejects duplicate node definitions.
type Builder struct {
	inv          model.Inventory
	seen         map[model.ID]model.SourceLocation
	placeholders map[string]bool
	errs         []error
}

// NewBuilder returns an empty builder.
func NewBuilder() *Builder {
	return &Builder{seen: map[model.ID]model.SourceLocation{}, placeholders: map[string]bool{}}
}

// Placeholder returns the unresolved placeholder for id and registers it.
// Normalizers create every placeholder through it; Build rejects any other.
func (b *Builder) Placeholder(id string) string {
	b.placeholders[id] = true
	return model.UnresolvedPlaceholder(id)
}

func (b *Builder) claim(id model.ID, identity string, src *model.SourceLocation) bool {
	if prev, dup := b.seen[id]; dup {
		b.errs = append(b.errs, fmt.Errorf("%w: %s is defined at %s and at %s", ErrDuplicate, identity, prev.String(), src.String()))
		return false
	}
	b.seen[id] = *src
	return true
}

// Has reports whether a node with this ID was added.
func (b *Builder) Has(id model.ID) bool {
	_, ok := b.seen[id]
	return ok
}

// AddPrincipal adds a principal node.
func (b *Builder) AddPrincipal(p *model.Principal) {
	if b.claim(p.ID(), p.Identity(), p.Source()) {
		b.inv.Principals = append(b.inv.Principals, p)
	}
}

// AddResource adds a resource node.
func (b *Builder) AddResource(r *model.Resource) {
	if b.claim(r.ID(), r.ARN(), r.Source()) {
		b.inv.Resources = append(b.inv.Resources, r)
	}
}

// AddWorkload adds a workload node.
func (b *Builder) AddWorkload(w *model.Workload) {
	if b.claim(w.ID(), w.Identity(), w.Source()) {
		b.inv.Workloads = append(b.inv.Workloads, w)
	}
}

// AddServiceAccount adds a service account (also a node).
func (b *Builder) AddServiceAccount(sa *model.ServiceAccount) {
	if b.claim(sa.ID, model.K8sIdentity(sa.Cluster, sa.Namespace, "ServiceAccount", sa.Name), &sa.Source) {
		b.inv.ServiceAccounts = append(b.inv.ServiceAccounts, sa)
	}
}

// AddCluster adds a cluster; a cluster may be described by several sources
// (Terraform, snapshot, config) only once.
func (b *Builder) AddCluster(c *model.Cluster) {
	if b.claim(model.NewID("cluster", c.Key()), "cluster "+c.Key(), &c.Source) {
		b.inv.Clusters = append(b.inv.Clusters, c)
	}
}

// ClusterKeys returns the keys of the clusters added so far whose name is
// name, sorted.
func (b *Builder) ClusterKeys(name string) []string {
	var out []string
	for _, c := range b.inv.Clusters {
		if c.Name == name && !slices.Contains(out, c.Key()) {
			out = append(out, c.Key())
		}
	}
	slices.Sort(out)
	return out
}

// Relation records. These attach to nodes and are not deduplicated by ID.

// AddPolicy attaches an identity or resource-based policy.
func (b *Builder) AddPolicy(p *model.AttachedPolicy) { b.inv.Policies = append(b.inv.Policies, p) }

// AddBoundary attaches a permissions boundary.
func (b *Builder) AddBoundary(p *model.AttachedPolicy) {
	b.inv.Boundaries = append(b.inv.Boundaries, p)
}

// AddTrust attaches a role trust policy.
func (b *Builder) AddTrust(t *model.TrustRelationship) { b.inv.Trusts = append(b.inv.Trusts, t) }

// AddExposure records a network exposure.
func (b *Builder) AddExposure(e *model.NetworkExposure) { b.inv.Exposures = append(b.inv.Exposures, e) }

// AddPodIdentity records an EKS Pod Identity association.
func (b *Builder) AddPodIdentity(p *model.PodIdentityAssociation) {
	b.inv.PodIdentity = append(b.inv.PodIdentity, p)
}

// AddNetworkPolicy records a Kubernetes NetworkPolicy.
func (b *Builder) AddNetworkPolicy(p *model.NetworkPolicy) {
	b.inv.NetworkPolicies = append(b.inv.NetworkPolicies, p)
}

// AddOIDCProvider records an IAM OIDC identity provider.
func (b *Builder) AddOIDCProvider(p *model.OIDCProvider) {
	b.inv.OIDCProviders = append(b.inv.OIDCProviders, p)
}

// AddAddon records a cluster add-on.
func (b *Builder) AddAddon(a *model.ClusterAddon) { b.inv.Addons = append(b.inv.Addons, a) }

// AddNodeGroup records a node group.
func (b *Builder) AddNodeGroup(n *model.NodeGroup) { b.inv.NodeGroups = append(b.inv.NodeGroups, n) }

// AddRBAC records a resolved RBAC grant.
func (b *Builder) AddRBAC(g *model.RBACGrant) { b.inv.RBAC = append(b.inv.RBAC, g) }

// AddMapping records an IAM-to-Kubernetes identity mapping.
func (b *Builder) AddMapping(m *model.IdentityMapping) { b.inv.Mappings = append(b.inv.Mappings, m) }

// Build sorts everything into a deterministic order and returns the
// inventory, or every duplicate-definition error found.
func (b *Builder) Build() (*model.Inventory, error) {
	b.checkPlaceholders()
	if len(b.errs) > 0 {
		return nil, errors.Join(b.errs...)
	}
	inv := b.inv
	sortByID(inv.Principals, (*model.Principal).ID)
	sortByID(inv.Resources, (*model.Resource).ID)
	sortByID(inv.Workloads, (*model.Workload).ID)
	slices.SortFunc(inv.ServiceAccounts, func(a, c *model.ServiceAccount) int { return strings.Compare(string(a.ID), string(c.ID)) })
	slices.SortFunc(inv.Clusters, func(a, c *model.Cluster) int { return strings.Compare(a.Key(), c.Key()) })
	sortPolicies(inv.Policies)
	sortPolicies(inv.Boundaries)
	slices.SortFunc(inv.Trusts, func(a, c *model.TrustRelationship) int { return strings.Compare(string(a.Role()), string(c.Role())) })
	slices.SortFunc(inv.Exposures, func(a, c *model.NetworkExposure) int {
		return cmp.Or(strings.Compare(string(a.Workload()), string(c.Workload())), strings.Compare(a.Via(), c.Via()))
	})
	slices.SortFunc(inv.PodIdentity, func(a, c *model.PodIdentityAssociation) int {
		return strings.Compare(a.Cluster+"/"+a.Namespace+"/"+a.ServiceAccount, c.Cluster+"/"+c.Namespace+"/"+c.ServiceAccount)
	})
	slices.SortFunc(inv.NetworkPolicies, func(a, c *model.NetworkPolicy) int {
		return strings.Compare(a.Cluster+"/"+a.Namespace+"/"+a.Name, c.Cluster+"/"+c.Namespace+"/"+c.Name)
	})
	slices.SortFunc(inv.OIDCProviders, func(a, c *model.OIDCProvider) int { return strings.Compare(a.ARN, c.ARN) })
	slices.SortFunc(inv.Addons, func(a, c *model.ClusterAddon) int { return strings.Compare(a.Cluster+"/"+a.Name, c.Cluster+"/"+c.Name) })
	slices.SortFunc(inv.NodeGroups, func(a, c *model.NodeGroup) int { return strings.Compare(a.Cluster+"/"+a.Name, c.Cluster+"/"+c.Name) })
	slices.SortFunc(inv.RBAC, compareRBAC)
	slices.SortFunc(inv.Mappings, func(a, c *model.IdentityMapping) int {
		return strings.Compare(a.Cluster+"/"+a.PrincipalARN, c.Cluster+"/"+c.PrincipalARN)
	})
	return &inv, nil
}

func sortByID[T any](xs []*T, id func(*T) model.ID) {
	slices.SortFunc(xs, func(a, b *T) int { return strings.Compare(string(id(a)), string(id(b))) })
}

func sortPolicies(ps []*model.AttachedPolicy) {
	slices.SortFunc(ps, func(a, b *model.AttachedPolicy) int {
		return cmp.Or(strings.Compare(string(a.Target), string(b.Target)), strings.Compare(a.Doc.ID(), b.Doc.ID()))
	})
}

func compareRBAC(a, b *model.RBACGrant) int {
	return cmp.Or(strings.Compare(a.Cluster, b.Cluster), strings.Compare(a.Namespace, b.Namespace),
		strings.Compare(a.SubjectKind, b.SubjectKind), strings.Compare(a.SubjectNamespace, b.SubjectNamespace),
		strings.Compare(a.SubjectName, b.SubjectName), strings.Compare(a.Source.String(), b.Source.String()))
}
