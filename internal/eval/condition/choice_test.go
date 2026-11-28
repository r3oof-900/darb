package condition

import (
	"slices"
	"testing"
)

// A choice counts only while every one of its keys is unknown: a stated
// key (or an assumption) wins over it.
func TestChoicesYieldToStatedKeys(t *testing.T) {
	open := Choice{Keys: []string{"aws:SecureTransport"}, Options: []Option{{"aws:SecureTransport": {"true"}}}}
	joint := Choice{Keys: []string{"aws:CalledVia", "aws:CalledViaLast"}, Options: []Option{{}}}
	ctx := NewContext(&Input{
		Default: StateUnknown, Present: map[string][]string{"AWS:CalledViaLast": {"s3.amazonaws.com"}},
		Choices: []Choice{open, joint},
	})
	got := ctx.Choices()
	if len(got) != 1 || got[0].Keys[0] != "aws:SecureTransport" {
		t.Fatalf("a choice one of whose keys is stated is dropped: %+v", got)
	}
	got[0].Options[0]["aws:SecureTransport"][0] = "changed"
	if ctx.Choices()[0].Options[0]["aws:SecureTransport"][0] != "true" {
		t.Error("Choices returns copies")
	}
}

// With sets the choice's keys as the option says: listed keys present,
// the others absent; the result has no choices left.
func TestWithSetsEveryKeyOfTheChoice(t *testing.T) {
	ctx := NewContext(&Input{Default: StateUnknown, Choices: []Choice{{Keys: []string{"k1"}, Options: []Option{{}}}}})
	w := ctx.With([]string{"K1", "k2"}, Option{"K1": {"v"}})
	if v := w.Lookup("k1"); v.State != StatePresent || !slices.Equal(v.Values, []string{"v"}) {
		t.Errorf("k1: %+v", v)
	}
	if v := w.Lookup("k2"); v.State != StateAbsent {
		t.Errorf("k2 is absent: %+v", v)
	}
	if v := w.Lookup("k3"); v.State != StateUnknown {
		t.Errorf("other keys keep the default: %+v", v)
	}
	if len(w.Choices()) != 0 || len(ctx.Choices()) != 1 {
		t.Error("With leaves no choices and does not change the original")
	}
}
