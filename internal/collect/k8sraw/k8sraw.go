package k8sraw

import (
	"cmp"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
)

// Pos is where an object starts (1-based line).
type Pos struct {
	File string
	Line int
}

// Object is one decoded Kubernetes object with its source position.
type Object struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	Obj        runtime.Object // a typed k8s.io/api object
	Pos        Pos
}

// Objects is what the manifest collector returns for one cluster.
type Objects struct {
	Cluster string
	Items   []*Object
}

// Sort orders objects by kind, namespace, name, then position.
func (o *Objects) Sort() {
	slices.SortFunc(o.Items, func(a, b *Object) int {
		return cmp.Or(strings.Compare(a.Kind, b.Kind), strings.Compare(a.Namespace, b.Namespace),
			strings.Compare(a.Name, b.Name), strings.Compare(a.Pos.File, b.Pos.File), cmp.Compare(a.Pos.Line, b.Pos.Line))
	})
}
