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
	// Kind, From, To: the edge drawn (data attributes: what a fix step
	// names can be found in the drawing).
	Kind, From, To string
	D              string
	Class          string // "" | "cut" | "resolve"
	Mark           string // ✂ for a cut edge, ? for a resolve step
	LX, LY         int
	Lines          []string
}

const keyDrop = 46 // a decrypted key's box sits this far below its row

// layout draws hops: nil when there is no path. A derived read is drawn as
// its parts: the read to the data, the decrypt down to the key (placed
// below, between the role and the data), the key protecting the data; the
// role and the data then share a row.
func layout(hs []schema.Hop, branches [][]schema.Hop) *diagram {
	if len(hs) == 0 {
		return nil
	}
	type end struct{ id, kind string }
	nodes := []end{{hs[0].From, hs[0].FromKind}}
	for _, h := range hs {
		nodes = append(nodes, end{h.To, h.ToKind})
	}
	stride := boxH + gapY
	for _, h := range hs {
		if keyOf(&h) != nil {
			stride = 2*boxH + keyDrop + gapY
		}
	}
	// Columns, skipping to the next row so a role and the data it reads
	// through a key stay on one row.
	xs, ys := make([]int, len(nodes)), make([]int, len(nodes))
	col, row, cols := 0, 0, 1
	for i := range nodes {
		if i < len(hs) && keyOf(&hs[i]) != nil && col == perRow-1 {
			col, row = 0, row+1
		}
		if col == perRow {
			col, row = 0, row+1
		}
		xs[i], ys[i] = margin+col*(boxW+gapX), margin+row*stride
		cols = max(cols, col+1)
		col++
	}
	d := &diagram{
		W:     2*margin + cols*boxW + (cols-1)*gapX,
		H:     2*margin + row*stride + boxH,
		Label: fmt.Sprintf("path of %d edges from %s to %s", len(hs), nodes[0].id, nodes[len(nodes)-1].id),
	}
	for i, n := range nodes {
		d.Nodes = append(d.Nodes, box(xs[i], ys[i], n.id, n.kind))
	}
	for i := range hs {
		h := &hs[i]
		key := keyOf(h)
		if key == nil {
			d.Edges = append(d.Edges, arrow(h, xs[i], ys[i], xs[i+1], ys[i+1]))
			continue
		}
		d.derived(h, key, xs[i], ys[i], xs[i+1], ys[i+1])
	}
	for _, b := range branches {
		d.branch(b)
	}
	return d
}

// branch draws a cut edge that is off the path (an escalation of a
// dominated path, merged into this cut) in a new row: from its source's box
// when drawn, down to its target, and from there up to the data.
func (d *diagram) branch(b []schema.Hop) {
	if len(b) == 0 {
		return
	}
	find := func(id, kind string) *diagramNode {
		for i := range d.Nodes {
			if n := &d.Nodes[i]; n.Full == id && n.Type == nodeType(kind) {
				return n
			}
		}
		return nil
	}
	h := &b[0]
	y := d.H - margin + gapY
	src := find(h.From, h.FromKind)
	var e diagramEdge
	var tx int
	if src != nil { // straight down from a quarter of the source's box
		tx = src.X
		e = diagramEdge{Kind: h.Kind, From: h.From, To: h.To, Class: h.Cut, Mark: mark(h.Cut), Lines: edgeLines(h.Kind)}
		e.D = fmt.Sprintf("M%d %dV%d", src.X+boxW/4, src.Y+boxH, y-4)
		e.LX, e.LY = src.X+boxW/4+8, y-gapY/2
	} else { // a source not on the path: its own box first
		d.Nodes = append(d.Nodes, box(margin, y, h.From, h.FromKind))
		tx = margin + boxW + gapX
		e = arrow(h, margin, y, tx, y)
	}
	d.Nodes = append(d.Nodes, box(tx, y, h.To, h.ToKind))
	d.Edges = append(d.Edges, e)
	d.W = max(d.W, tx+boxW+margin)
	d.H = y + boxH + margin
	if len(b) < 2 {
		return
	}
	n := &b[1]
	if dst := find(n.To, n.ToKind); dst != nil { // right, then up to the data
		up := diagramEdge{Kind: n.Kind, From: n.From, To: n.To, Class: n.Cut, Mark: mark(n.Cut), Lines: edgeLines(n.Kind)}
		x := max(dst.X+boxW-20, tx+boxW+30)
		up.D = fmt.Sprintf("M%d %dH%dV%d", tx+boxW, y+boxH/2, x, dst.Y+boxH+4)
		up.LX, up.LY = tx+boxW+8, y+boxH/2-6
		d.Edges = append(d.Edges, up)
		d.W = max(d.W, x+margin)
	}
}

// derived draws a derived read's parts: the decrypt down to the key (its
// box below, between the role at x1 and the data at x2), the key
// protecting the data, the read straight to the data.
func (d *diagram) derived(h, key *schema.Hop, x1, y1, x2, y2 int) {
	kx, ky := x1+(boxW+gapX)/2, y1+boxH+keyDrop
	d.H = max(d.H, ky+boxH+margin)
	d.Nodes = append(d.Nodes, box(kx, ky, key.To, key.ToKind))
	for j := range h.Parts {
		p := &h.Parts[j]
		e := diagramEdge{Kind: p.Kind, From: p.From, To: p.To, Class: p.Cut, Mark: mark(p.Cut), Lines: edgeLines(p.Kind)}
		switch p.Kind {
		case "CAN_DECRYPT": // down from the role, then right to the key
			e.D = fmt.Sprintf("M%d %dV%d", x1+boxW/2, y1+boxH, ky+boxH/2) + fmt.Sprintf("H%d", kx-4)
			e.LX, e.LY = x1+boxW/2+6, y1+boxH+16
		case "PROTECTS": // up from the key to the data
			e.D = fmt.Sprintf("M%d %dV%d", x2+10, ky, y2+boxH+4)
			e.LX, e.LY = x2+16, ky-8
		default: // the read, straight to the data
			e = arrow(p, x1, y1, x2, y2)
		}
		d.Edges = append(d.Edges, e)
	}
}

// keyOf: the decrypt among a derived read's parts, if any.
func keyOf(h *schema.Hop) *schema.Hop {
	for i := range h.Parts {
		if h.Parts[i].Kind == "CAN_DECRYPT" {
			return &h.Parts[i]
		}
	}
	return nil
}

func box(x, y int, id, kind string) diagramNode {
	return diagramNode{X: x, Y: y, TX: x + 10, TY: y + 20, NY: y + 40, Class: nodeClass(kind), Type: nodeType(kind), Name: short(id), Full: id}
}

func mark(cut string) string {
	switch cut {
	case "cut":
		return "✂"
	case "resolve":
		return "?"
	}
	return ""
}

// arrow: an edge between two boxes, straight on one row, otherwise down,
// back to the first column and down again.
func arrow(h *schema.Hop, x1, y1, x2, y2 int) diagramEdge {
	e := diagramEdge{Kind: h.Kind, From: h.From, To: h.To, Class: h.Cut, Mark: mark(h.Cut), Lines: edgeLines(h.Kind)}
	if y1 == y2 {
		e.D = fmt.Sprintf("M%d %dH%d", x1+boxW, y1+boxH/2, x2-4)
		e.LX, e.LY = x1+boxW+8, y1+boxH/2-6-12*(len(e.Lines)-1)
		return e
	}
	mid := y2 - gapY/2
	e.D = fmt.Sprintf("M%d %dV%dH%dV%d", x1+boxW/2, y1+boxH, mid, x2+boxW/2, y2-4)
	e.LX, e.LY = x2+boxW/2+8, mid-4-12*(len(e.Lines)-1)
	return e
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
