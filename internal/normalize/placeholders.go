package normalize

import (
	"fmt"
	"slices"

	"github.com/r3oof-900/clapa/internal/model"
)

// checkPlaceholders records an error for every placeholder in the inventory
// that Placeholder did not create.
func (b *Builder) checkPlaceholders() {
	var bad []string
	seen := map[string]bool{}
	for _, s := range inventoryStrings(&b.inv) {
		for _, id := range model.UnresolvedIDs(s) {
			if !b.placeholders[id] && !seen[id] {
				seen[id] = true
				bad = append(bad, id)
			}
		}
	}
	slices.Sort(bad)
	for _, id := range bad {
		b.errs = append(b.errs, fmt.Errorf("%w: %s", ErrUnregisteredPlaceholder, model.UnresolvedPlaceholder(id)))
	}
}

// inventoryStrings lists every string of the inventory that analysis reads.
// TestInventoryStringsComplete keeps it in step with the model.
func inventoryStrings(inv *model.Inventory) []string {
	var out []string
	add := func(ss ...string) { out = append(out, ss...) }
	for _, p := range inv.Principals {
		add(p.Identity(), p.Account())
	}
	for _, r := range inv.Resources {
		e := r.Encryption()
		add(r.ARN(), r.Account(), r.Region(), e.Type, e.KeyARN)
		for _, t := range r.Tags() {
			add(t.Key, t.Value)
		}
	}
	for _, w := range inv.Workloads {
		add(w.Identity(), w.Namespace(), w.ServiceAccount())
	}
	for _, sa := range inv.ServiceAccounts {
		add(sa.Cluster, sa.Namespace, sa.Name, sa.RoleARN, sa.Audience)
	}
	for _, c := range inv.Clusters {
		add(c.Name, c.ARN, c.Account, c.Region, c.OIDCIssuer)
	}
	for _, ps := range [][]*model.AttachedPolicy{inv.Policies, inv.Boundaries} {
		for _, p := range ps {
			out = append(out, policyStrings(p.Doc)...)
		}
	}
	for _, t := range inv.Trusts {
		out = append(out, policyStrings(t.Policy())...)
	}
	return append(out, eksStrings(inv)...)
}

// eksStrings lists the strings of the EKS and Kubernetes access records.
func eksStrings(inv *model.Inventory) []string {
	var out []string
	add := func(ss ...string) { out = append(out, ss...) }
	for _, a := range inv.PodIdentity {
		add(a.Cluster, a.Namespace, a.ServiceAccount, a.RoleARN, a.TargetRoleARN)
	}
	for _, a := range inv.Addons {
		add(a.Cluster, a.Name)
	}
	for _, ng := range inv.NodeGroups {
		add(ng.Cluster, ng.Name, ng.RoleARN, ng.HTTPTokens, ng.HTTPEndpoint)
	}
	for _, g := range inv.RBAC {
		add(g.Cluster, g.Namespace, g.SubjectKind, g.SubjectNamespace, g.SubjectName)
		for _, r := range g.Rules {
			add(r.APIGroups...)
			add(r.Resources...)
			add(r.Verbs...)
			add(r.ResourceNames...)
		}
	}
	for _, m := range inv.Mappings {
		add(m.Cluster, m.PrincipalARN, m.Username)
		add(m.Groups...)
	}
	return out
}

func policyStrings(d *model.PolicyDocument) []string {
	var out []string
	for _, s := range d.Statements() {
		acts, _ := s.Actions()
		res, _ := s.Resources()
		out = append(append(out, acts...), res...)
		if p, _ := s.Principal(); p != nil {
			for _, r := range p.Refs() {
				out = append(out, r.Value)
			}
		}
		for _, c := range s.Conditions() {
			out = append(append(out, c.Key()), c.Values()...)
		}
	}
	return out
}
