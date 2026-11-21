package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A fake proxy: two modules, one released long before --at, one the day before.
func fakeProxy(t *testing.T) *httptest.Server {
	t.Helper()
	times := map[string]string{
		"/example.com/old/@v/v1.0.0.info":    `{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`,
		"/example.com/!fresh/@v/v1.2.0.info": `{"Version":"v1.2.0","Time":"2026-11-20T00:00:00Z"}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := times[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func goMod(t *testing.T, requires string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "go.mod")
	if err := os.WriteFile(p, []byte("module m\n\ngo 1.26\n\nrequire (\n"+requires+")\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDepage(t *testing.T) {
	srv := fakeProxy(t)
	for _, tc := range []struct {
		name, requires, want string
		code                 int
	}{
		{"old only", "\texample.com/old v1.0.0\n", "all 1 requirements", 0},
		{"one too new (path escaped)", "\texample.com/old v1.0.0\n\texample.com/Fresh v1.2.0 // indirect\n", "too new: example.com/Fresh v1.2.0", 1},
		{"unknown to the proxy", "\texample.com/missing v1.0.0\n", "", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run(context.Background(), []string{"--at", "2026-11-21T00:00:00Z", "--proxy", srv.URL, goMod(t, tc.requires)}, &out, &errOut, srv.Client())
			if code != tc.code || !strings.Contains(out.String(), tc.want) {
				t.Fatalf("code %d, out %q, err %q", code, out.String(), errOut.String())
			}
		})
	}
}

func TestDepageMinAge(t *testing.T) {
	srv := fakeProxy(t)
	var out bytes.Buffer
	// The fresh module is one day old: allowed with --min-age 12h.
	code := run(context.Background(), []string{"--at", "2026-11-21T00:00:00Z", "--min-age", "12h", "--proxy", srv.URL, goMod(t, "\texample.com/Fresh v1.2.0\n")}, &out, &out, srv.Client())
	if code != 0 {
		t.Fatalf("code %d: %s", code, out.String())
	}
}

func TestDepageUsage(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), []string{"--at", "yesterday"}, &out, &out, http.DefaultClient); code != 2 {
		t.Fatalf("bad --at: code %d", code)
	}
	if code := run(context.Background(), []string{filepath.Join(t.TempDir(), "none")}, &out, &out, http.DefaultClient); code != 2 {
		t.Fatalf("missing go.mod: code %d", code)
	}
}
