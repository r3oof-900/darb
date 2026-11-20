package manifests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"

	"go.yaml.in/yaml/v3"
	"k8s.io/apimachinery/pkg/runtime"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/k8sraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/safeio"
)

// Name identifies this collector in coverage gaps.
const Name = "k8s-manifests"

// maxAliases bounds YAML aliases per document (alias-expansion bombs).
const maxAliases = 64

// Options configure the collector.
type Options struct {
	Cluster string // canonical cluster name used in IDs (docs/DESIGN.md section 5)
}

// Collect decodes every YAML/JSON manifest under in.Path (multi-document,
// Helm- or Kustomize-rendered output) into k8s.io/api types. Unknown kinds
// and unknown fields are warnings with file:line; a malformed file is
// reported and the scan continues with the next file.
func Collect(ctx context.Context, in *collect.Input, opts *Options, rec *coverage.Recorder) (*k8sraw.Objects, error) {
	base := filepath.Join(in.Root, filepath.FromSlash(in.Path))
	files, err := safeio.Walk(base, []string{".yaml", ".yml", ".json"})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	s, err := newSerializer()
	if err != nil {
		return nil, err
	}
	d := &decoder{rec: rec, limits: in.Limits, serializer: s}
	out := &k8sraw.Objects{Cluster: opts.Cluster}
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		name := filepath.ToSlash(filepath.Join(in.Path, f))
		data, err := safeio.ReadFile(base, f, in.Limits)
		if err != nil {
			d.gap(coverage.KindParseError, name, 0, err.Error())
			continue
		}
		out.Items = append(out.Items, d.file(name, data)...)
	}
	out.Sort()
	return out, nil
}

type decoder struct {
	rec        *coverage.Recorder
	limits     safeio.Limits
	serializer *kjson.Serializer
}

func (d *decoder) gap(kind coverage.Kind, file string, line int, detail string) {
	d.rec.Add(&coverage.Gap{Kind: kind, Source: Name, File: file, Line: line, Detail: detail})
}

// file splits a file into YAML documents (JSON is valid YAML).
func (d *decoder) file(name string, data []byte) []*k8sraw.Object {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []*k8sraw.Object
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			d.gap(coverage.KindParseError, name, yamlErrorLine(err), err.Error())
			return out // the rest of this file cannot be trusted; other files continue
		}
		if obj := d.document(name, &doc); obj != nil {
			out = append(out, obj)
		}
	}
}

var lineRE = regexp.MustCompile(`line (\d+)`)

func yamlErrorLine(err error) int {
	if m := lineRE.FindStringSubmatch(err.Error()); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// document decodes one YAML document into a typed object.
func (d *decoder) document(name string, doc *yaml.Node) *k8sraw.Object {
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil // empty document or a bare scalar
	}
	root := doc.Content[0]
	if depth, aliases := measure(root, 1); depth > d.limits.MaxDepth || aliases > maxAliases {
		d.gap(coverage.KindParseError, name, root.Line, fmt.Sprintf("document exceeds limits (depth %d, aliases %d)", depth, aliases))
		return nil
	}
	if line, found := reserved(root); found {
		// Rejected as invalid input: the document is not loaded.
		d.gap(coverage.KindParseError, name, line, collect.ErrReservedText.Error()+"; document rejected")
		return nil
	}
	js, err := toJSON(root)
	if err != nil {
		d.gap(coverage.KindParseError, name, root.Line, err.Error())
		return nil
	}
	var meta struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(js, &meta) // a document without these fields fails typed decoding below
	return d.typed(name, root.Line, js, meta.APIVersion, meta.Kind, meta.Metadata.Name, meta.Metadata.Namespace)
}

func (d *decoder) typed(name string, line int, js []byte, apiVersion, kind, objName, ns string) *k8sraw.Object {
	obj, _, err := d.serializer.Decode(js, nil, nil)
	switch {
	case err != nil && runtime.IsNotRegisteredError(err):
		d.gap(coverage.KindUnsupported, name, line, fmt.Sprintf("unsupported kind %s %s (skipped)", apiVersion, kind))
		return nil
	case err != nil && runtime.IsStrictDecodingError(err) && obj != nil:
		d.gap(coverage.KindUnsupported, name, line, fmt.Sprintf("%s %s: %v", kind, objName, err))
	case err != nil:
		d.gap(coverage.KindParseError, name, line, fmt.Sprintf("%s %s: %v", kind, objName, err))
		return nil
	}
	if !supported(kind) {
		d.gap(coverage.KindUnsupported, name, line, fmt.Sprintf("kind %s is not analysed (skipped)", kind))
		return nil
	}
	return &k8sraw.Object{APIVersion: apiVersion, Kind: kind, Namespace: ns, Name: objName, Obj: obj, Pos: k8sraw.Pos{File: name, Line: line}}
}

// measure returns the nesting depth and alias count of a node tree.
func measure(n *yaml.Node, depth int) (maxDepth, aliases int) {
	maxDepth = depth
	if n.Kind == yaml.AliasNode {
		aliases++
	}
	for _, c := range n.Content {
		d, a := measure(c, depth+1)
		maxDepth, aliases = max(maxDepth, d), aliases+a
	}
	return maxDepth, aliases
}

func toJSON(n *yaml.Node) ([]byte, error) {
	y, err := yaml.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("re-encode document: %w", err)
	}
	js, err := sigsyaml.YAMLToJSON(y)
	if err != nil {
		return nil, fmt.Errorf("convert document to JSON: %w", err)
	}
	return js, nil
}

// reserved finds a key or value (decoded by YAML, escapes included) that
// contains the reserved placeholder text, and returns its line.
func reserved(n *yaml.Node) (int, bool) {
	if n.Kind == yaml.ScalarNode && collect.ContainsReserved(n.Value) {
		return n.Line, true
	}
	for _, c := range n.Content {
		if line, ok := reserved(c); ok {
			return line, true
		}
	}
	return 0, false
}
