package remediate

import (
	"fmt"
	"slices"

	"github.com/r3oof-900/clapa/internal/model"
)

// Apply returns a copy of inv with the edits made; inv is not changed. Every
// policy document an edit names must exist, and every statement index too.
func Apply(inv *model.Inventory, edits []Edit) (*model.Inventory, error) {
	out := *inv
	byDoc := map[string][]Edit{}
	var order []string
	for i := range edits {
		e := &edits[i]
		switch e.Op {
		case OpAddStatement, OpRemoveValues, OpRemoveStatement, OpSetValues:
			if _, seen := byDoc[e.Policy]; !seen {
				order = append(order, e.Policy)
			}
			byDoc[e.Policy] = append(byDoc[e.Policy], *e)
		case OpNodeMetadata, OpRemoveHostNetwork, OpRemoveExposure, OpRestrictPublic, OpDisableTokenMount, OpDetachPolicy:
			applyFact(&out, e)
		}
	}
	for _, id := range order {
		if err := applyDocument(inv, &out, id, byDoc[id]); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

// applyFact makes an edit that is not a policy edit.
func applyFact(out *model.Inventory, e *Edit) {
	switch e.Op {
	case OpNodeMetadata:
		out.NodeGroups = replaceNodeGroup(out.NodeGroups, e)
	case OpRemoveHostNetwork:
		out.Workloads = replaceAll(out.Workloads, func(w *model.Workload) *model.Workload {
			if w.ID() == e.Workload.ID() {
				return w.WithoutHostNetwork()
			}
			return w
		})
	case OpDisableTokenMount:
		out.Workloads = replaceAll(out.Workloads, func(w *model.Workload) *model.Workload {
			if w.ID() == e.Workload.ID() {
				return w.WithoutTokenMount()
			}
			return w
		})
	case OpRemoveExposure:
		out.Exposures = slices.DeleteFunc(slices.Clone(out.Exposures), func(x *model.NetworkExposure) bool {
			return *x.Source() == *e.Exposure.Source()
		})
	case OpRestrictPublic:
		out.Resources = replaceAll(out.Resources, func(r *model.Resource) *model.Resource {
			if r.ID() != e.Bucket.ID() {
				return r
			}
			s := r.S3()
			s.RestrictPublicBuckets = model.True
			return r.WithS3(s)
		})
	case OpDetachPolicy:
		out.Policies = slices.DeleteFunc(slices.Clone(out.Policies), func(a *model.AttachedPolicy) bool {
			return a.Target == e.Principal.ID() && a.Doc.ID() == e.Policy
		})
	case OpAddStatement, OpRemoveValues, OpRemoveStatement, OpSetValues:
	}
}

// applyDocument rebuilds policy id with its edits wherever it is attached.
func applyDocument(inv, out *model.Inventory, id string, edits []Edit) error {
	doc := Document(inv, id)
	if doc == nil {
		return fmt.Errorf("remediate: policy %s is not in the inventory", id)
	}
	changed, err := editDocument(doc, edits)
	if err != nil {
		return err
	}
	out.Policies = replacePolicy(out.Policies, id, changed)
	out.Boundaries = replacePolicy(out.Boundaries, id, changed)
	out.Trusts = replaceAll(out.Trusts, func(t *model.TrustRelationship) *model.TrustRelationship {
		if t.Policy() != nil && t.Policy().ID() == id {
			return model.NewTrustRelationship(t.Role(), changed)
		}
		return t
	})
	return nil
}

// editDocument rebuilds a policy document with the edits: value removals,
// statement removals (by original index), then the added statements.
func editDocument(doc *model.PolicyDocument, edits []Edit) (*model.PolicyDocument, error) {
	stmts := doc.Statements()
	inputs := make([]*model.StatementInput, len(stmts))
	for i, s := range stmts {
		inputs[i] = s.Input()
	}
	removed := map[int]bool{}
	var added []*model.StatementInput
	for i := range edits {
		e := &edits[i]
		if e.Op == OpAddStatement {
			added = append(added, e.Statement)
			continue
		}
		if e.Index < 0 || e.Index >= len(inputs) {
			return nil, fmt.Errorf("remediate: %s has no statement %d", doc.ID(), e.Index)
		}
		switch {
		case e.Op == OpSetValues:
			setValues(inputs[e.Index], e)
		case e.Op == OpRemoveStatement || removeValues(inputs[e.Index], e):
			removed[e.Index] = true
		}
	}
	var kept []*model.StatementInput
	for i, in := range inputs {
		if !removed[i] {
			kept = append(kept, in)
		}
	}
	return model.NewPolicyDocument(&model.PolicyInput{
		ID: doc.ID(), Kind: doc.Kind(), Version: doc.Version(), Source: *doc.Source(), Statements: append(kept, added...),
	})
}

// setValues makes the element exactly e.Values: Resource (not NotResource),
// or an AWS Principal (not NotPrincipal).
func setValues(in *model.StatementInput, e *Edit) {
	if e.Element == "Resource" {
		in.Resource, in.NotResource = slices.Clone(e.Values), nil
		return
	}
	refs := make([]model.PrincipalRef, len(e.Values))
	for i, v := range e.Values {
		refs[i] = model.PrincipalRef{Type: model.PrincipalAWS, Value: v}
	}
	in.Principal, in.NotPrincipal = model.NewPrincipalSpec(false, refs), nil
}

// removeValues removes e.Values from the statement's element; true when the
// element is left empty (the statement goes).
func removeValues(in *model.StatementInput, e *Edit) bool {
	drop := func(v string) bool { return slices.Contains(e.Values, v) }
	if e.Element == "Resource" {
		in.Resource = slices.DeleteFunc(in.Resource, drop)
		return len(in.Resource) == 0
	}
	if in.Principal == nil {
		return false
	}
	refs := slices.DeleteFunc(in.Principal.Refs(), func(r model.PrincipalRef) bool { return drop(r.Value) })
	in.Principal = model.NewPrincipalSpec(in.Principal.Wildcard(), refs)
	return len(refs) == 0 && !in.Principal.Wildcard()
}

func replacePolicy(aps []*model.AttachedPolicy, id string, doc *model.PolicyDocument) []*model.AttachedPolicy {
	return replaceAll(aps, func(ap *model.AttachedPolicy) *model.AttachedPolicy {
		if ap.Doc.ID() == id {
			c := *ap
			c.Doc = doc
			return &c
		}
		return ap
	})
}

func replaceNodeGroup(ngs []*model.NodeGroup, e *Edit) []*model.NodeGroup {
	return replaceAll(ngs, func(ng *model.NodeGroup) *model.NodeGroup {
		if ng.Cluster != e.NodeGroup.Cluster || ng.Name != e.NodeGroup.Name {
			return ng
		}
		c := *ng
		if e.Endpoint != "" {
			c.HTTPEndpoint = e.Endpoint
		} else {
			c.HTTPTokens, c.HopLimit = e.Tokens, e.HopLimit
		}
		return &c
	})
}

func replaceAll[T any](xs []T, f func(T) T) []T {
	out := make([]T, len(xs))
	for i, x := range xs {
		out[i] = f(x)
	}
	return out
}
