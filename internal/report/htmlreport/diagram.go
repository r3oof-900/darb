package htmlreport

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/r3oof-900/clapa/pkg/schema"
)

// The path view (DESIGN.md §11): one box per node, one arrow per edge with
// its kind, laid out left to right and wrapped every few boxes. Computed
// here, rendered by the template: every coordinate is a number, every name
// a text node, the colours CSS classes (no inline style, so the CSP stays
// as it is), and no script draws anything.

const (
	boxW    = 180
	boxH    = 54
	gapX    = 140
	gapY    = 70
	margin  = 10
	perRow  = 4
	nameMax = 24
)

type diagram struct {
	W, H  int
	Label string
	Nodes []diagramNode
	Edges []diagramEdge
}

type diagramNode struct {
	X, Y        int
	TX, TY, NY  int
	Class, Type string
	Name, Full  string
}

type diagramEdge struct {
	D      string
	Class  string // "" | "cut" | "resolve"
	Mark   string // ✂ for a cut edge, ? for a resolve step
	LX, LY int
	Lines  []string
}

// layout draws hops: nil when there is no path.
func layout(hs []schema.Hop) *diagram {
	if len(hs) == 0 {
		return nil
	}
	type end struct{ id, kind string }
	nodes := []end{{hs[0].From, hs[0].FromKind}}
	for _, h := range hs {
		nodes = append(nodes, end{h.To, h.ToKind})
	}
	cols := min(len(nodes), perRow)
	rows := (len(nodes) + perRow - 1) / perRow
	d := &diagram{
		W:     2*margin + cols*boxW + (cols-1)*gapX,
		H:     2*margin + rows*boxH + (rows-1)*gapY,
		Label: fmt.Sprintf("path of %d edges from %s to %s", len(hs), nodes[0].id, nodes[len(nodes)-1].id),
	}
	pos := func(i int) (x, y int) {
		return margin + (i%perRow)*(boxW+gapX), margin + (i/perRow)*(boxH+gapY)
	}
	for i, n := range nodes {
		x, y := pos(i)
		d.Nodes = append(d.Nodes, diagramNode{
			X: x, Y: y, TX: x + 10, TY: y + 20, NY: y + 40,
			Class: nodeClass(n.kind), Type: nodeType(n.kind), Name: short(n.id), Full: n.id,
		})
	}
	for i, h := range hs {
		x1, y1 := pos(i)
		x2, y2 := pos(i + 1)
		e := diagramEdge{Class: h.Cut, Lines: edgeLines(h.Kind)}
		switch h.Cut {
		case "cut":
			e.Mark = "✂"
		case "resolve":
			e.Mark = "?"
		}
		if y1 == y2 { // same row: a straight arrow, its kind above it
			e.D = fmt.Sprintf("M%d %dH%d", x1+boxW, y1+boxH/2, x2-4)
			e.LX, e.LY = x1+boxW+8, y1+boxH/2-6-12*(len(e.Lines)-1)
		} else { // wrap: down, back to the first column, down again
			mid := y1 + boxH + gapY/2
			e.D = fmt.Sprintf("M%d %dV%dH%dV%d", x1+boxW/2, y1+boxH, mid, x2+boxW/2, y2-4)
			e.LX, e.LY = x2+boxW/2+8, mid-4-12*(len(e.Lines)-1)
		}
		d.Edges = append(d.Edges, e)
	}
	return d
}

// edgeLines: an edge kind on one line, or two when it has a qualifier
// (CAN_ESCALATE / [iam:modify-policy]), so it fits between the boxes.
func edgeLines(kind string) []string {
	if i := strings.IndexByte(kind, '['); i > 0 {
		return []string{kind[:i], kind[i:]}
	}
	return []string{kind}
}

// short: the last part of an identity, at most nameMax runes (the full
// identity is the box's title).
func short(id string) string {
	if i := strings.LastIndexAny(id, "/:"); i >= 0 && i < len(id)-1 {
		id = id[i+1:]
	}
	if utf8.RuneCountInString(id) > nameMax {
		r := []rune(id)
		id = string(r[:nameMax-1]) + "…"
	}
	return id
}

var nodeTypes = map[string][2]string{
	"k8s:workload":                {"workload", "workload"},
	"k8s:serviceaccount":          {"account", "service account"},
	"k8s:user":                    {"account", "Kubernetes user"},
	"k8s:group":                   {"account", "Kubernetes group"},
	"k8s:secret":                  {"data", "Kubernetes Secret"},
	"aws:iam:role":                {"role", "IAM role"},
	"aws:iam:role:any-permission": {"role", "role, any permission"},
	"aws:iam:user":                {"role", "IAM user"},
	"aws:kms:key":                 {"key", "KMS key"},
	"aws:s3:bucket":               {"data", "S3 bucket"},
	"aws:secretsmanager:secret":   {"data", "secret"},
	"aws:ssm:parameter":           {"data", "SSM parameter"},
	"aws:anonymous":               {"other", "anyone"},
	"net:internet":                {"other", "internet"},
}

func nodeClass(kind string) string {
	if t, ok := nodeTypes[kind]; ok {
		return t[0]
	}
	return "other"
}

func nodeType(kind string) string {
	if t, ok := nodeTypes[kind]; ok {
		return t[1]
	}
	return kind
}
