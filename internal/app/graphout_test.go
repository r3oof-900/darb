package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
)

// An identity from the input stays one quoted DOT string: a quote, a
// backslash or a line break cannot end it or add attributes; an UNKNOWN
// edge is dashed.
func TestDOTEscapesIdentities(t *testing.T) {
	hostile := "a\"]; evil [label=\"x\\nnew"
	b := graph.NewBuilder()
	from := b.Node(model.NewID(model.KindIAMRole, hostile), model.KindIAMRole, hostile)
	to := b.Node(model.NewID(model.KindS3Bucket, "arn:aws:s3:::b"), model.KindS3Bucket, "arn:aws:s3:::b")
	b.Edge(&graph.Edge{From: from, To: to, Kind: graph.CanRead, For: graph.NoNode, Verdict: eval.Unknown})
	var out bytes.Buffer
	if err := WriteGraph(&out, "dot", &Analysis{AccessGraph: b.Build()}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	quoted := `"a\"]; evil [label=\"x\\nnew"`
	if !strings.Contains(s, "  "+quoted+" -> \"arn:aws:s3:::b\" [label=\"CAN_READ\", style=dashed];") || strings.Count(s, "\n") != 7 {
		t.Fatalf("dot:\n%s", s)
	}
	if err := WriteGraph(&out, "svg", &Analysis{AccessGraph: b.Build()}); err == nil {
		t.Error("an unknown format is written")
	}
}
