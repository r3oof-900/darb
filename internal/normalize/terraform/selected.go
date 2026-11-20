package terraform

import (
	"github.com/r3oof-900/clapa/internal/collect/tfraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/model"
)

// roleIndex finds role nodes by name, by full address and, for references
// that select an instance by an expression the plan does not reveal, by the
// address without instance key.
type roleIndex struct {
	byKey     map[string]model.ID   // "root|role name", "root|address"
	instances map[string][]model.ID // "root|config address" -> every instance, in input order
}

func newRoleIndex() *roleIndex {
	return &roleIndex{byKey: map[string]model.ID{}, instances: map[string][]model.ID{}}
}

func (x *roleIndex) add(n *norm, r *tfraw.Resource, id model.ID) {
	x.byKey[r.Root+"|"+n.nameOf(r)] = id
	x.byKey[r.Root+"|"+r.Address] = id
	cfg := r.Root + "|" + r.ConfigAddress()
	x.instances[cfg] = append(x.instances[cfg], id)
}

// roleTarget is a role a policy is attached to. Uncertain: the policy is
// attached to one of several instances and the input does not say which.
type roleTarget struct {
	id        model.ID
	uncertain bool
}

// roleTargets resolves a "role" attribute: a reference to a role resource, or
// a role name. aws_iam_role.r[each.value].id gives every instance of
// aws_iam_role.r as an uncertain target: the plan records the selector but
// not its value (each.value of a map is not the key). A role that is not in
// the input is a coverage gap.
func (n *norm) roleTargets(r *tfraw.Resource, v *tfraw.Value, roles *roleIndex) []roleTarget {
	if v != nil && v.Kind == tfraw.KRef {
		if v.Ref.Selector == "" {
			if id, ok := roles.byKey[r.Root+"|"+v.Ref.Address]; ok {
				return []roleTarget{{id: id}}
			}
		} else if ids := roles.instances[r.Root+"|"+v.Ref.Address]; len(ids) > 0 {
			n.gap(coverage.KindUnresolved, r, "role is one instance of "+v.Ref.Address+" selected by "+v.Ref.Selector+
				", which the plan does not record; the policy may apply to each instance (UNKNOWN)")
			out := make([]roleTarget, len(ids))
			for i, id := range ids {
				out[i] = roleTarget{id: id, uncertain: true}
			}
			return out
		}
	}
	if name, ok := n.str(r.Root, v); ok {
		if id, ok := roles.byKey[r.Root+"|"+name]; ok {
			return []roleTarget{{id: id}}
		}
	}
	n.gap(coverage.KindUnresolved, r, "attached role is not defined in the input; this policy is not attached to any analysed role")
	return nil
}

// attach adds d to each target. For an uncertain target every statement gets
// an extra condition on an unresolved key, so each Allow and each Deny is
// UNKNOWN there: whether it applies depends on the selection.
func (n *norm) attach(r *tfraw.Resource, targets []roleTarget, d *model.PolicyDocument) {
	for _, t := range targets {
		doc := d
		if t.uncertain {
			doc = n.onlyIfSelected(d, n.placeholder("selects."+r.Address+"->"+string(t.id)))
		}
		n.b.AddPolicy(&model.AttachedPolicy{Target: t.id, Doc: doc})
	}
}

func (n *norm) onlyIfSelected(d *model.PolicyDocument, key string) *model.PolicyDocument {
	in := &model.PolicyInput{ID: d.ID(), Kind: d.Kind(), Version: d.Version(), Source: *d.Source()}
	for _, s := range d.Statements() {
		st := &model.StatementInput{Sid: s.Sid(), Effect: s.Effect(), Conditions: s.Conditions()}
		if acts, neg := s.Actions(); neg {
			st.NotAction = acts
		} else {
			st.Action = acts
		}
		if res, neg := s.Resources(); neg {
			st.NotResource = res
		} else {
			st.Resource = res
		}
		if p, neg := s.Principal(); neg {
			st.NotPrincipal = p
		} else {
			st.Principal = p
		}
		st.Conditions = append(st.Conditions, model.NewCondition("StringEquals", key, []string{"selected"}))
		in.Statements = append(in.Statements, st)
	}
	out, err := model.NewPolicyDocument(in)
	if err != nil { // unreachable: the statements came from a valid document
		return n.unknownDoc(d.ID(), d.Kind(), d.Source())
	}
	return out
}
