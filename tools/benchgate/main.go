// Command benchgate fails when a benchmark got significantly slower: the
// head's median sec/op is more than 20% above the base's, and a two-sided
// Mann-Whitney U test gives p < 0.05 (the statistics benchstat uses).
// Usage: benchgate base.txt head.txt
package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
)

const (
	maxRegression = 0.20
	alpha         = 0.05
)

func main() {
	if len(os.Args) != 3 {
		_, _ = fmt.Fprintln(os.Stderr, "usage: benchgate base.txt head.txt")
		os.Exit(2)
	}
	base, err := readFile(os.Args[1])
	if err == nil {
		var head map[string][]float64
		head, err = readFile(os.Args[2])
		if err == nil {
			failed := report(os.Stdout, base, head)
			if failed {
				os.Exit(1)
			}
			return
		}
	}
	_, _ = fmt.Fprintln(os.Stderr, "benchgate:", err)
	os.Exit(2)
}

func readFile(path string) (map[string][]float64, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a path given on the command line by the CI job.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parse(f)
}

// parse reads "go test -bench" output: the ns/op of every sample, by name.
func parse(r io.Reader) (map[string][]float64, error) {
	out := map[string][]float64{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || !strings.HasPrefix(fields[0], "Benchmark") {
			continue
		}
		for i := 2; i+1 < len(fields); i += 2 {
			if fields[i+1] == "ns/op" {
				v, err := strconv.ParseFloat(fields[i], 64)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", fields[0], err)
				}
				out[fields[0]] = append(out[fields[0]], v)
			}
		}
	}
	return out, sc.Err()
}

// report prints one line per benchmark present in both runs and returns
// whether any regressed significantly.
func report(w io.Writer, base, head map[string][]float64) bool {
	names := make([]string, 0, len(base))
	for name := range base {
		if _, ok := head[name]; ok {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	failed := false
	for _, name := range names {
		b, h := median(base[name]), median(head[name])
		delta := (h - b) / b
		p := mannWhitney(base[name], head[name])
		verdict := "ok"
		if delta > maxRegression && p < alpha {
			verdict, failed = "REGRESSION", true
		}
		_, _ = fmt.Fprintf(w, "%-60s %12.0f -> %12.0f ns/op  %+6.1f%%  p=%.3f  %s\n", name, b, h, 100*delta, p, verdict)
	}
	return failed
}

func median(xs []float64) float64 {
	s := slices.Clone(xs)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// mannWhitney returns the two-sided p-value of the Mann-Whitney U test, with
// the normal approximation and tie correction (adequate for 10 samples each).
func mannWhitney(a, b []float64) float64 {
	type obs struct {
		v     float64
		first bool
	}
	all := make([]obs, 0, len(a)+len(b))
	for _, v := range a {
		all = append(all, obs{v, true})
	}
	for _, v := range b {
		all = append(all, obs{v, false})
	}
	slices.SortFunc(all, func(x, y obs) int {
		switch {
		case x.v < y.v:
			return -1
		case x.v > y.v:
			return 1
		}
		return 0
	})
	n1, n2 := float64(len(a)), float64(len(b))
	rankSum, ties := 0.0, 0.0
	for i := 0; i < len(all); {
		j := i
		for j < len(all) && all[j].v == all[i].v {
			j++
		}
		rank := float64(i+j+1) / 2 // average rank of the tie group (1-based)
		t := float64(j - i)
		ties += t*t*t - t
		for k := i; k < j; k++ {
			if all[k].first {
				rankSum += rank
			}
		}
		i = j
	}
	u := rankSum - n1*(n1+1)/2
	mean := n1 * n2 / 2
	n := n1 + n2
	sd := math.Sqrt(n1 * n2 / 12 * ((n + 1) - ties/(n*(n-1))))
	if sd == 0 {
		return 1
	}
	z := (math.Abs(u-mean) - 0.5) / sd
	return math.Erfc(math.Max(z, 0) / math.Sqrt2)
}
