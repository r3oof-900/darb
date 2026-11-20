package rules

import (
	"errors"
	"testing"
)

type stub struct{ m Meta }

func (s *stub) Meta() Meta { return s.m }

func (s *stub) Evaluate(*Input) []Finding {
	return []Finding{{Resource: "b"}, {Resource: "a"}}
}

func TestRegistry(t *testing.T) {
	if _, err := NewRegistry(&stub{Meta{ID: "X"}}, &stub{Meta{ID: "X"}}); !errors.Is(err, ErrDuplicateRule) {
		t.Fatalf("duplicate IDs: %v", err)
	}
	r, err := NewRegistry(&stub{Meta{ID: "B", Version: "2.1.0", Kind: KindPosture}}, &stub{Meta{ID: "A", Version: "1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if rs := r.Rules(); rs[0].Meta().ID != "A" {
		t.Error("rules sorted by ID")
	}
	if _, ok := r.Get("B"); !ok {
		t.Error("Get")
	}
	if _, ok := r.Get("C"); ok {
		t.Error("Get unknown")
	}
	fs := r.Evaluate(&Input{})
	if len(fs) != 4 || fs[0].Rule != "A" || fs[0].Resource != "a" || fs[3].Version != "2.1.0" || fs[3].DefaultsUsed == nil {
		t.Errorf("findings: %+v", fs)
	}
	for v, want := range map[string]string{"2.1.0": "2", "3": "3"} {
		m := Meta{Version: v}
		if m.Major() != want {
			t.Errorf("Major(%s)", v)
		}
	}
}
