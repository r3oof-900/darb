// Command depage fails when a go.mod requirement (direct or indirect) was
// released less than --min-age before --at: dependencies must be at least
// two weeks old. Release times come from the Go module proxy's .info files.
//
//	go run ./tools/depage [--at RFC3339] [--min-age 336h] [--proxy URL] [go.mod]
//
// CI passes the commit time as --at, so a commit's result does not change
// with the day it is checked.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, http.DefaultClient))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, client *http.Client) int {
	fs := flag.NewFlagSet("depage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	at := fs.String("at", "", "reference time, RFC 3339 (default: now)")
	minAge := fs.Duration("min-age", 14*24*time.Hour, "minimum age of every requirement")
	proxy := fs.String("proxy", "https://proxy.golang.org", "Go module proxy")
	allowFile := fs.String("allow", "tools/depage/allow.yaml", "exceptions for security fixes (see allow.go)")
	if err := fs.Parse(args); err != nil || fs.NArg() > 1 {
		return 2
	}
	ref := time.Now()
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "depage: --at:", err)
			return 2
		}
		ref = t
	}
	file := "go.mod"
	if fs.NArg() == 1 {
		file = fs.Arg(0)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "depage:", err)
		return 2
	}
	mf, err := modfile.ParseLax(file, data, nil)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "depage:", err)
		return 2
	}
	entries, err := loadAllow(*allowFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "depage:", err)
		return 2
	}
	f := &fetcher{client: client, proxy: strings.TrimSuffix(*proxy, "/")}
	c := &checker{f: f, cutoff: ref.Add(-*minAge), ref: ref, allow: entries}
	tooNew, err := c.check(ctx, mf.Require, stdout)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "depage:", err)
		return 2
	}
	for _, line := range tooNew {
		_, _ = fmt.Fprintln(stdout, line)
	}
	if len(tooNew) > 0 {
		_, _ = fmt.Fprintf(stdout, "%d requirement(s) released after %s (younger than %s)\n", len(tooNew), ref.Add(-*minAge).Format(time.RFC3339), *minAge)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "all %d requirements released before %s\n", len(mf.Require), ref.Add(-*minAge).Format(time.RFC3339))
	return 0
}

// checker compares each requirement's release time with the cutoff.
type checker struct {
	f      *fetcher
	cutoff time.Time
	ref    time.Time
	allow  []allowEntry
}

// check returns the requirements that are too new and not allowed; it
// prints each allowed one, with its advisory and expiry.
func (c *checker) check(ctx context.Context, reqs []*modfile.Require, stdout io.Writer) ([]string, error) {
	var out []string
	for _, r := range reqs {
		t, err := c.f.released(ctx, r.Mod.Path, r.Mod.Version)
		if err != nil {
			return nil, err
		}
		if !t.After(c.cutoff) {
			continue
		}
		line := fmt.Sprintf("too new: %s %s released %s", r.Mod.Path, r.Mod.Version, t.Format(time.RFC3339))
		switch e, ok := allowed(c.allow, r.Mod.Path, r.Mod.Version, c.ref); {
		case ok:
			_, _ = fmt.Fprintln(stdout, "allowed:", r.Mod.Path, r.Mod.Version, "released", t.Format(time.RFC3339),
				"("+e.Advisory+", until "+e.Expires+": "+e.Reason+")")
		case e != nil:
			out = append(out, line+" (its exception for "+e.Advisory+" expired on "+e.Expires+")")
		default:
			out = append(out, line)
		}
	}
	sort.Strings(out)
	return out, nil
}

type fetcher struct {
	client *http.Client
	proxy  string
}

var errStatus = errors.New("unexpected status")

func (f *fetcher) released(ctx context.Context, path, version string) (time.Time, error) {
	ep, err := module.EscapePath(path)
	if err != nil {
		return time.Time{}, err
	}
	ev, err := module.EscapeVersion(version)
	if err != nil {
		return time.Time{}, err
	}
	url := f.proxy + "/" + ep + "/@v/" + ev + ".info"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return time.Time{}, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("%s: %w %d", url, errStatus, resp.StatusCode)
	}
	var info struct {
		Time time.Time `json:"Time"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&info); err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", url, err)
	}
	return info.Time, nil
}
