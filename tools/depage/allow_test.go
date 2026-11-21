package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fake proxy (main_test.go) has example.com/Fresh v1.2.0 released one
// day before --at 2026-11-21.
const freshReq = "\texample.com/Fresh v1.2.0\n"

func allowFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "allow.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func entry(fields map[string]string) string {
	var b strings.Builder
	first := true
	for _, k := range []string{"module", "version", "reason", "advisory", "expires"} {
		v, ok := fields[k]
		if !ok {
			continue
		}
		if first {
			b.WriteString("- ")
			first = false
		} else {
			b.WriteString("  ")
		}
		b.WriteString(k + ": " + v + "\n")
	}
	return b.String()
}

func full() map[string]string {
	return map[string]string{
		"module": "example.com/Fresh", "version": "v1.2.0", "reason": "fixes a request smuggling bug",
		"advisory": "GO-2026-1234", "expires": "2026-12-01",
	}
}

func without(k string) map[string]string { m := full(); delete(m, k); return m }

func with(k, v string) map[string]string { m := full(); m[k] = v; return m }

func runAllow(t *testing.T, allow string) (code int, out string) {
	t.Helper()
	srv := fakeProxy(t)
	var stdout, stderr bytes.Buffer
	code = run(context.Background(), []string{"--at", "2026-11-21T00:00:00Z", "--proxy", srv.URL, "--allow", allow, goMod(t, freshReq)}, &stdout, &stderr, srv.Client())
	return code, stdout.String() + stderr.String()
}

func TestAllowEntryLetsASecurityFixIn(t *testing.T) {
	code, out := runAllow(t, allowFile(t, entry(full())))
	if code != 0 || !strings.Contains(out, "allowed: example.com/Fresh v1.2.0") || !strings.Contains(out, "GO-2026-1234, until 2026-12-01") {
		t.Fatalf("code %d\n%s", code, out)
	}
	if code, out := runAllow(t, allowFile(t, entry(with("advisory", "CVE-2026-12345")))); code != 0 {
		t.Fatalf("a CVE is an advisory too: %d\n%s", code, out)
	}
}

// Without its reason, advisory or expiry date, or with a malformed one,
// the file is rejected: exit 2, before any requirement is checked.
func TestAllowEntryRequiresEveryField(t *testing.T) {
	for name, fields := range map[string]map[string]string{
		"no reason":           without("reason"),
		"no advisory":         without("advisory"),
		"advisory not GO/CVE": with("advisory", "GHSA-xxxx-yyyy-zzzz"),
		"advisory malformed":  with("advisory", "GO-26-1"),
		"no expires":          without("expires"),
		"expires malformed":   with("expires", "next month"),
		"no module":           without("module"),
		"no version":          without("version"),
	} {
		if code, out := runAllow(t, allowFile(t, entry(fields))); code != 2 || !strings.Contains(out, "invalid allow file") {
			t.Errorf("%s: code %d\n%s", name, code, out)
		}
	}
	if code, _ := runAllow(t, allowFile(t, entry(full())+"  owner: me\n")); code != 2 {
		t.Error("an unknown field is rejected")
	}
	if _, err := loadAllow(allowFile(t, entry(without("reason")))); !errors.Is(err, errNoReason) {
		t.Errorf("err %v", err)
	}
}

// After its expiry date the exception ends and the check blocks again;
// an exception is for exactly one version.
func TestAllowEntryExpiresAndIsExact(t *testing.T) {
	code, out := runAllow(t, allowFile(t, entry(with("expires", "2026-11-21"))))
	if code != 1 || !strings.Contains(out, "its exception for GO-2026-1234 expired on 2026-11-21") {
		t.Fatalf("expired: code %d\n%s", code, out)
	}
	if code, out := runAllow(t, allowFile(t, entry(with("version", "v1.1.0")))); code != 1 || strings.Contains(out, "allowed:") {
		t.Fatalf("another version: code %d\n%s", code, out)
	}
	if code, _ := runAllow(t, filepath.Join(t.TempDir(), "none.yaml")); code != 1 {
		t.Fatal("no allow file allows nothing")
	}
	if code, _ := runAllow(t, allowFile(t, "")); code != 1 {
		t.Fatal("an empty allow file allows nothing")
	}
}
