package terraform

import (
	"github.com/r3oof-900/darb/internal/collect/tfraw"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/normalize"
)

// kmsGrant: an aws_kms_grant gives its grantee_principal its operations on
// the key (AWS provider › aws_kms_grant; KMS Developer Guide › Grants in
// AWS KMS). It becomes a resource policy of the key (normalize.GrantPolicy)
// whose ID names the resource, so a fix of that side deletes it.
func (n *norm) kmsGrant(r *tfraw.Resource) {
	key := n.keyRef(r, "key_id", "")
	if key == "" {
		n.gap(coverage.KindUnresolved, r, "key_id is not set; the grant is not attached")
		return
	}
	g := &normalize.Grant{ID: r.Address}
	g.Grantee, _ = n.str(r.Root, attr(r, "grantee_principal"))
	ops := attr(r, "operations")
	if ops == nil || ops.Kind != tfraw.KList {
		n.gap(coverage.KindUnresolved, r, "operations are not known statically; the grant is not attached")
		return
	}
	for _, op := range ops.List {
		s, _ := n.str(r.Root, op)
		g.Operations = append(g.Operations, s)
	}
	for _, c := range r.Attrs.Blocks("constraints") {
		g.Equals = n.stringMap(r, c, "encryption_context_equals")
		g.Subset = n.stringMap(r, c, "encryption_context_subset")
	}
	id := normalize.GrantDocID(key, r.Address)
	n.b.AddPolicy(&model.AttachedPolicy{
		Target: model.NewID(model.KindKMSKey, key),
		Doc:    n.parsePolicy(r, id, model.PolicyResource, normalize.GrantPolicy(g), true),
	})
}

// stringMap reads a map attribute of a block; a value that is not known
// statically keeps its placeholder, which the evaluator treats as UNKNOWN.
func (n *norm) stringMap(r *tfraw.Resource, block *tfraw.Object, key string) map[string]string {
	v, ok := block.Get(key)
	if !ok || v.Kind != tfraw.KObject || v.Obj == nil {
		if ok && v.Kind != tfraw.KNull {
			n.gap(coverage.KindUnresolved, r, "constraints."+key+" is not known statically")
			return map[string]string{n.placeholder(r.Address + ".constraints.key"): n.placeholder(r.Address + ".constraints." + key)}
		}
		return nil
	}
	out := map[string]string{}
	for _, k := range v.Obj.Keys() {
		val, _ := v.Obj.Get(k)
		out[k], _ = n.str(r.Root, val)
	}
	return out
}
