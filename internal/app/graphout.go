package app

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/graph"
)

// GraphFormats are the formats of darb graph.
func GraphFormats() []string { return []string{"dot", "json"} }

// GraphVersion identifies the JSON form of darb graph.
const GraphVersion = "darb-graph/v1"

type graphNode struct {
	Identity string `json:"identity"`
	Kind     string `json:"kind"`
}

type graphEdge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Kind       string `json:"kind"` // as findings name it: CAN_ESCALATE[iam:modify-policy], CAN_DECRYPT[for J]
	Verdict    string `json:"verdict"`
	Confidence string `json:"confidence"`
	DenyOnly   bool   `json:"deny_only,omitempty"`
	Derived    bool   `json:"derived,omitempty"` // CAN_READ_PLAINTEXT standing for a read and a decrypt
}

type graphDoc struct {
	Schema string      `json:"schema"`
	Nodes  []graphNode `json:"nodes"`
	Edges  []graphEdge `json:"edges"`
}

// graphOf is the access graph in a stable order: nodes by identity, edges
// by their description (DESIGN.md §3.4: same input, same bytes).
func graphOf(g *graph.Graph) graphDoc {
	doc := graphDoc{Schema: GraphVersion, Nodes: []graphNode{}, Edges: []graphEdge{}}
	for i := range g.NumNodes() {
		n := g.Node(graph.NodeID(i))
		doc.Nodes = append(doc.Nodes, graphNode{Identity: n.Identity, Kind: string(n.Kind)})
	}
	slices.SortFunc(doc.Nodes, func(a, b graphNode) int {
		return cmp.Or(strings.Compare(a.Identity, b.Identity), strings.Compare(a.Kind, b.Kind))
	})
	for i := range g.NumEdges() {
		id := graph.EdgeID(i)
		e := g.Edge(id)
		kind := graph.Label(e)
		if e.Kind == graph.CanEscalate && e.Sub != "" {
			kind += "[" + e.Sub + "]"
		}
		if e.For != graph.NoNode {
			kind += "[for " + g.Node(e.For).Identity + "]"
		}
		doc.Edges = append(doc.Edges, graphEdge{
			From: g.Node(e.From).Identity, To: g.Node(e.To).Identity, Kind: kind,
			Verdict: e.Verdict.String(), Confidence: e.Confidence.String(), DenyOnly: e.DenyOnly, Derived: len(e.Under) > 0,
		})
	}
	slices.SortFunc(doc.Edges, func(a, b graphEdge) int {
		return cmp.Or(strings.Compare(a.From, b.From), strings.Compare(a.To, b.To), strings.Compare(a.Kind, b.Kind))
	})
	return doc
}

// WriteGraph writes the access graph of an analysis: JSON (darb-graph/v1)
// or Graphviz DOT. Every identity comes from the input and is written as an
// escaped string, never as markup.
func WriteGraph(w io.Writer, format string, a *Analysis) error {
	doc := graphOf(a.AccessGraph)
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(doc)
	case "dot":
		return writeDOT(w, &doc)
	}
	return fmt.Errorf("%w %q (one of %v)", ErrFormat, format, GraphFormats())
}

// dotQuote is a DOT double-quoted string: backslashes, quotes and line
// breaks escaped, so a name cannot end the string or add attributes.
func dotQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`)
	return `"` + r.Replace(s) + `"`
}

func writeDOT(w io.Writer, doc *graphDoc) error {
	var b strings.Builder
	b.WriteString("digraph darb {\n  rankdir=LR;\n  node [shape=box, fontname=\"monospace\"];\n")
	for _, n := range doc.Nodes {
		fmt.Fprintf(&b, "  %s [label=%s];\n", dotQuote(n.Identity), dotQuote(n.Identity+"\n"+n.Kind))
	}
	for _, e := range doc.Edges {
		style := "solid"
		switch {
		case e.Verdict != "ALLOW":
			style = "dashed" // rests on an UNKNOWN
		case e.Derived:
			style = "bold"
		}
		fmt.Fprintf(&b, "  %s -> %s [label=%s, style=%s];\n", dotQuote(e.From), dotQuote(e.To), dotQuote(e.Kind), style)
	}
	b.WriteString("}\n")
	_, err := io.WriteString(w, b.String())
	return err
}
