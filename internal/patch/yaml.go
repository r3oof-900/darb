package patch

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/r3oof-900/clapa/internal/remediate"
)

// Kubernetes manifests are edited line by line at the lines a YAML parser
// located: a key is removed only when it is alone on its line, a key is
// added with the indentation of its siblings.

// yamlDoc finds the manifest kind/namespace/name of a multi-document file;
// address is "Kind/namespace/name" (DESIGN.md §5).
func yamlDoc(data []byte, address string) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("patch: %s is not in the file", address)
		}
		if err != nil {
			return nil, fmt.Errorf("patch: manifest does not parse: %w", err)
		}
		if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
			continue
		}
		root := doc.Content[0]
		meta := mapValue(root, "metadata")
		ns := "default"
		if n := mapValue(meta, "namespace"); n != nil {
			ns = n.Value
		}
		if k := mapValue(root, "kind"); k != nil && k.Value+"/"+ns+"/"+scalar(mapValue(meta, "name")) == address ||
			k != nil && k.Value+"//"+scalar(mapValue(meta, "name")) == address {
			return root, nil
		}
	}
}

func scalar(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	return n.Value
}

// mapValue is the value of key in a mapping node (nil if absent).
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func mapKey(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i]
		}
	}
	return nil
}

// podSpec is the pod spec of a workload manifest.
func podSpec(root *yaml.Node) *yaml.Node {
	kind := scalar(mapValue(root, "kind"))
	spec := mapValue(root, "spec")
	switch kind {
	case "Pod":
		return spec
	case "CronJob":
		return mapValue(mapValue(mapValue(mapValue(spec, "jobTemplate"), "spec"), "template"), "spec")
	}
	return mapValue(mapValue(spec, "template"), "spec")
}

// lineOffset is the byte offset of 1-based line n.
func lineOffset(src []byte, n int) int {
	off := 0
	for i := 1; i < n; i++ {
		j := bytes.IndexByte(src[off:], '\n')
		if j < 0 {
			return len(src)
		}
		off += j + 1
	}
	return off
}

// removeHostNetwork deletes the `hostNetwork: true` line of the workload.
func (p *patcher) removeHostNetwork(e *remediate.Edit) error {
	src := e.Workload.Source()
	t, err := p.text(src.File())
	if err != nil {
		return err
	}
	root, err := yamlDoc(t.src, src.Address())
	if err != nil {
		return err
	}
	k := mapKey(podSpec(root), "hostNetwork")
	if k == nil {
		return fmt.Errorf("patch: %s has no hostNetwork", src.Address())
	}
	off := lineOffset(t.src, k.Line)
	line := strings.TrimSpace(string(t.src[off:t.lineEnd(off)]))
	if !strings.HasPrefix(line, "hostNetwork:") || strings.Contains(line, ",") {
		return todo("hostNetwork of %s is not on a line of its own: remove it by hand", src.Address())
	}
	t.deleteLines(off, off)
	return nil
}

// removeExposure makes a LoadBalancer or NodePort Service a ClusterIP one:
// the `type:` value is replaced. A Service that names node ports, or whose
// type is not on a line of its own, is changed by hand.
func (p *patcher) removeExposure(e *remediate.Edit) error {
	src := e.Exposure.Source()
	t, err := p.text(src.File())
	if err != nil {
		return err
	}
	root, err := yamlDoc(t.src, src.Address())
	if err != nil {
		return err
	}
	spec := mapValue(root, "spec")
	typ := mapValue(spec, "type")
	if typ == nil || typ.Style != 0 {
		return todo("the type of %s is not a plain value: make it ClusterIP by hand", src.Address())
	}
	if ports := mapValue(spec, "ports"); ports != nil {
		for _, port := range ports.Content {
			if mapValue(port, "nodePort") != nil {
				return todo("%s names node ports, which a ClusterIP Service cannot have: remove them and make it ClusterIP by hand", src.Address())
			}
		}
	}
	off := lineOffset(t.src, typ.Line) + typ.Column - 1
	t.replace(off, off+len(typ.Value), "ClusterIP")
	return nil
}

// validYAML: the edited manifest still parses.
func validYAML(data []byte) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var n yaml.Node
		if err := dec.Decode(&n); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return fmt.Errorf("patch: the edited manifest does not parse: %w", err)
		}
	}
}
