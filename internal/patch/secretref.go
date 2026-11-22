package patch

import (
	"fmt"

	yaml "go.yaml.in/yaml/v3"

	"github.com/r3oof-900/darb/internal/remediate"
)

// removeSecretRef deletes every reference to a Secret from a workload's
// pod spec: the secret volumes that name it and the volumeMounts of those
// volumes, the env entries whose valueFrom.secretKeyRef names it and the
// envFrom entries whose secretRef names it, in every container, init and
// ephemeral container. Whole list items are deleted (a list left empty
// loses its key). A flow-style list, or a projected volume that also has
// other sources, is changed by hand.
func (p *patcher) removeSecretRef(e *remediate.Edit) error {
	src := e.Workload.Source()
	t, err := p.text(src.File())
	if err != nil {
		return err
	}
	root, err := yamlDoc(t.src, src.Address())
	if err != nil {
		return err
	}
	spec := podSpec(root)
	if spec == nil || spec.Style != 0 {
		return todo("the pod spec of %s is not a block mapping: stop naming Secret %s by hand", src.Address(), e.Secret)
	}
	r := &refRemover{t: t, secret: e.Secret, address: src.Address()}
	volumes := map[string]bool{}
	if err := r.list(spec, "volumes", func(v *yaml.Node) (bool, error) {
		if scalar(mapValue(mapValue(v, "secret"), "secretName")) == e.Secret {
			volumes[scalar(mapValue(v, "name"))] = true
			return true, nil
		}
		if srcs := mapValue(mapValue(v, "projected"), "sources"); srcs != nil {
			for _, s := range srcs.Content {
				if scalar(mapValue(mapValue(s, "secret"), "name")) == e.Secret {
					return false, todo("projected volume %s of %s also names Secret %s: remove that source by hand", scalar(mapValue(v, "name")), src.Address(), e.Secret)
				}
			}
		}
		return false, nil
	}); err != nil {
		return err
	}
	for _, key := range []string{"initContainers", "containers", "ephemeralContainers"} {
		list := mapValue(spec, key)
		if list == nil {
			continue
		}
		for _, c := range list.Content {
			if err := r.container(c, volumes); err != nil {
				return err
			}
		}
	}
	if r.removed == 0 {
		return fmt.Errorf("patch: %s does not name Secret %s", src.Address(), e.Secret)
	}
	return nil
}

type refRemover struct {
	t       *text
	secret  string
	address string
	removed int
}

func (r *refRemover) container(c *yaml.Node, volumes map[string]bool) error {
	if err := r.list(c, "env", func(v *yaml.Node) (bool, error) {
		return scalar(mapValue(mapValue(mapValue(v, "valueFrom"), "secretKeyRef"), "name")) == r.secret, nil
	}); err != nil {
		return err
	}
	if err := r.list(c, "envFrom", func(v *yaml.Node) (bool, error) {
		return scalar(mapValue(mapValue(v, "secretRef"), "name")) == r.secret, nil
	}); err != nil {
		return err
	}
	return r.list(c, "volumeMounts", func(v *yaml.Node) (bool, error) {
		return volumes[scalar(mapValue(v, "name"))], nil
	})
}

// list deletes the items of m[key] that drop selects, line by line; when
// every item goes, the key goes too.
func (r *refRemover) list(m *yaml.Node, key string, drop func(*yaml.Node) (bool, error)) error {
	seq := mapValue(m, key)
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil
	}
	var gone []*yaml.Node
	for _, item := range seq.Content {
		d, err := drop(item)
		if err != nil {
			return err
		}
		if d {
			gone = append(gone, item)
		}
	}
	if len(gone) == 0 {
		return nil
	}
	if seq.Style != 0 {
		return todo("%s of %s is a flow-style list: stop naming Secret %s by hand", key, r.address, r.secret)
	}
	r.removed += len(gone)
	if len(gone) == len(seq.Content) {
		k := mapKey(m, key)
		r.t.deleteLines(lineOffset(r.t.src, k.Line), lineOffset(r.t.src, lastLine(seq)))
		return nil
	}
	for _, item := range gone {
		r.t.deleteLines(lineOffset(r.t.src, item.Line), lineOffset(r.t.src, lastLine(item)))
	}
	return nil
}

// lastLine is the last line a node's content is on.
func lastLine(n *yaml.Node) int {
	last := n.Line
	for _, c := range n.Content {
		last = max(last, lastLine(c))
	}
	return last
}
