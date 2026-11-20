package main

import (
	"bytes"
	"strings"
	"testing"
)

func run(base, head []float64) (string, bool) {
	var buf bytes.Buffer
	failed := report(&buf, map[string][]float64{"BenchmarkX": base}, map[string][]float64{"BenchmarkX": head, "BenchmarkOnlyHead": {1}})
	return buf.String(), failed
}

func TestGate(t *testing.T) {
	base := []float64{100, 101, 99, 100, 102, 98, 100, 101, 99, 100}
	slower := []float64{130, 131, 129, 130, 132, 128, 130, 131, 129, 130}
	noisy := []float64{60, 200, 90, 150, 70, 180, 95, 140, 80, 160}
	same := []float64{100, 100, 101, 99, 100, 101, 99, 100, 100, 101}
	if out, failed := run(base, slower); !failed || !strings.Contains(out, "REGRESSION") {
		t.Errorf("30%% slower, significant: %s", out)
	}
	if _, failed := run(base, same); failed {
		t.Error("unchanged must pass")
	}
	if out, failed := run(base, noisy); failed {
		t.Errorf("a noisy run that is not significantly slower must pass: %s", out)
	}
	if _, failed := run(slower, base); failed {
		t.Error("faster must pass")
	}
	if p := mannWhitney([]float64{1, 1}, []float64{1, 1}); p != 1 {
		t.Errorf("all ties: p = %v", p)
	}
	if median([]float64{3, 1, 2}) != 2 || median([]float64{4, 1, 3, 2}) != 2.5 {
		t.Error("median")
	}
}

func TestParse(t *testing.T) {
	in := `goos: linux
BenchmarkAnalyze/small-12   	       3	  74876133 ns/op	72499896 B/op	  734832 allocs/op
BenchmarkAnalyze/small-12   	       3	  70000000 ns/op	72499896 B/op	  734832 allocs/op
PASS
`
	got, err := parse(strings.NewReader(in))
	if err != nil || len(got["BenchmarkAnalyze/small-12"]) != 2 || got["BenchmarkAnalyze/small-12"][1] != 70000000 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := parse(strings.NewReader("BenchmarkBad 3 notanumber ns/op\n")); err == nil {
		t.Error("a bad number must fail")
	}
}
