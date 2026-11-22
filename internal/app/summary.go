package app

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/r3oof-900/clapa/internal/classify"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/model"
)

// Summary renders a Loaded inventory as deterministic, indented JSON: the
// golden-file format of tests/fixtures/*/normalized.golden.json. Every slice
// is already sorted by the builder; maps render with sorted keys.
func Summary(l *Loaded) ([]byte, error) {
	inv := l.Inventory
	names := map[model.ID]string{}
	s := map[string]any{"collected": l.Collected}
	s["principals"] = mapSlice(inv.Principals, func(p *model.Principal) any {
		names[p.ID()] = p.Identity()
		return map[string]any{"kind": p.Kind(), "identity": p.Identity(), "account": p.Account(), "source": loc(p.Source())}
	})
	s["resources"] = mapSlice(inv.Resources, func(r *model.Resource) any {
		names[r.ID()] = r.ARN()
		class, by := r.Classification()
		m := map[string]any{
			"kind": r.Kind(), "arn": r.ARN(), "account": r.Account(), "region": r.Region(),
			"classification": class, "classified_by": by, "source": loc(r.Source()), "defaulted": nonNil(r.Defaulted()),
		}
		if r.Kind() == model.KindKMSKey {
			m["key_rotation"] = r.KeyRotation().String()
		}
		if r.Kind() == model.KindS3Bucket { // these facts only mean something for buckets
			m["encryption"] = r.Encryption()
			m["restrict_public_buckets"] = r.S3().RestrictPublicBuckets.String()
		}
		return m
	})
	kubernetesSummary(s, inv, names)
	s["policies"] = mapSlice(inv.Policies, policySummary(names))
	s["boundaries"] = mapSlice(inv.Boundaries, policySummary(names))
	s["trusts"] = mapSlice(inv.Trusts, func(t *model.TrustRelationship) any {
		return docSummary(names[t.Role()], t.Policy())
	})
	s["exposures"] = mapSlice(inv.Exposures, func(e *model.NetworkExposure) any {
		return map[string]any{"workload": names[e.Workload()], "via": e.Via(), "public": e.Public().String()}
	})
	s["pod_identity"] = mapSlice(inv.PodIdentity, func(p *model.PodIdentityAssociation) any {
		return map[string]any{
			"cluster": p.Cluster, "service_account": p.Namespace + "/" + p.ServiceAccount, "role_arn": p.RoleARN,
			"target_role_arn": p.TargetRoleARN, "session_tags_disabled": p.SessionTagsDisabled.String(),
			"defaulted": nonNil(p.Defaulted), "source": loc(&p.Source),
		}
	})
	s["network_policies"] = mapSlice(inv.NetworkPolicies, func(p *model.NetworkPolicy) any {
		return map[string]any{
			"cluster": p.Cluster, "namespace": p.Namespace, "name": p.Name, "default_deny_ingress": p.DefaultDenyIngress(),
			"defaulted": nonNil(p.Defaulted), "source": loc(&p.Source),
		}
	})
	s["addons"] = mapSlice(inv.Addons, func(a *model.ClusterAddon) any {
		return map[string]any{"cluster": a.Cluster, "name": a.Name, "source": loc(&a.Source)}
	})
	s["node_groups"] = mapSlice(inv.NodeGroups, func(n *model.NodeGroup) any {
		return map[string]any{
			"cluster": n.Cluster, "name": n.Name, "role_arn": n.RoleARN, "http_tokens": n.HTTPTokens,
			"hop_limit": n.HopLimit, "http_endpoint": n.HTTPEndpoint, "source": loc(&n.Source),
		}
	})
	s["rbac"] = mapSlice(inv.RBAC, func(g *model.RBACGrant) any {
		return map[string]any{
			"cluster": g.Cluster, "namespace": g.Namespace, "subject": g.SubjectKind + ":" + g.SubjectNamespace + "/" + g.SubjectName,
			"rules": g.Rules, "unresolved": g.Unresolved, "source": loc(&g.Source),
		}
	})
	s["mappings"] = mapSlice(inv.Mappings, func(m *model.IdentityMapping) any {
		return map[string]any{"cluster": m.Cluster, "principal": m.PrincipalARN, "username": m.Username, "groups": m.Groups, "source": loc(&m.Source)}
	})
	s["entry_points"] = mapSlice(ptrs(l.EntryPoints), func(e *classify.EntryPoint) any {
		return map[string]any{"workload": names[e.Workload], "reason": e.Reason, "public": e.Public.String()}
	})
	s["gaps"] = mapSlice(l.Gaps, func(g coverage.Gap) any { return g })
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("summary: %w", err)
	}
	return append(out, '\n'), nil
}

func policySummary(names map[model.ID]string) func(p *model.AttachedPolicy) any {
	return func(p *model.AttachedPolicy) any {
		m, _ := docSummary(names[p.Target], p.Doc).(map[string]any)
		if p.Default != "" {
			m["default"] = p.Default
		}
		return m
	}
}

// docSummary records a policy's shape and whether it holds unresolved values.
func docSummary(target string, d *model.PolicyDocument) any {
	var stmts []string
	unresolved := 0
	for _, st := range d.Statements() {
		acts, notA := st.Actions()
		res, notR := st.Resources()
		on := not(notR) + strings.Join(res, ",")
		if len(res) == 0 {
			on = "<no Resource element>"
		}
		line := fmt.Sprintf("%s %s%s on %s (%d conditions)", st.Effect(), not(notA), strings.Join(acts, ","), on, len(st.Conditions()))
		if model.ContainsUnresolved(line) {
			unresolved++
		}
		stmts = append(stmts, line)
	}
	return map[string]any{
		"target": target, "policy": d.ID(), "kind": d.Kind().String(), "statements": stmts,
		"unresolved_statements": unresolved, "source": loc(d.Source()),
	}
}

func not(neg bool) string {
	if neg {
		return "NOT "
	}
	return ""
}

func loc(s *model.SourceLocation) string { return s.String() }

func mapSlice[T any](xs []T, f func(T) any) []any {
	out := make([]any, 0, len(xs))
	for _, x := range xs {
		out = append(out, f(x))
	}
	return out
}

func ptrs[T any](xs []T) []*T {
	out := make([]*T, len(xs))
	for i := range xs {
		out[i] = &xs[i]
	}
	return out
}

// nonNil renders an empty list as [] rather than null.
func nonNil(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

// kubernetesSummary adds workloads, service accounts and clusters.
func kubernetesSummary(s map[string]any, inv *model.Inventory, names map[model.ID]string) {
	s["workloads"] = mapSlice(inv.Workloads, func(w *model.Workload) any {
		names[w.ID()] = w.Identity()
		out := map[string]any{
			"identity": w.Identity(), "service_account": w.ServiceAccount(),
			"host_network": w.HostNetwork(), "privileged": w.Privileged(), "automount_token": w.AutomountToken().String(),
			"defaulted": nonNil(w.Defaulted()), "source": loc(w.Source()),
		}
		// Phase 7: only when the pod spec names a Secret, so the goldens of
		// workloads that name none are unchanged.
		if refs := w.SecretRefs(); len(refs) > 0 {
			out["secret_refs"] = refs
		}
		return out
	})
	s["service_accounts"] = mapSlice(inv.ServiceAccounts, func(sa *model.ServiceAccount) any {
		return map[string]any{
			"cluster": sa.Cluster, "subject": sa.SubjectString(), "role_arn": sa.RoleARN,
			"audience": sa.Audience, "automount_token": sa.AutomountToken.String(), "defaulted": nonNil(sa.Defaulted), "source": loc(&sa.Source),
		}
	})
	s["clusters"] = mapSlice(inv.Clusters, func(c *model.Cluster) any {
		return map[string]any{
			"name": c.Name, "arn": c.ARN, "account": c.Account, "region": c.Region,
			"oidc_issuer": c.OIDCIssuer, "source": loc(&c.Source),
		}
	})
}
