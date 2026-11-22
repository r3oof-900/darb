package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ghToken = "gh" + "p_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// jsonLines parses every line as a JSON object.
func jsonLines(t *testing.T, s string) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("not a JSON line: %q (%v)", sc.Text(), err)
		}
		out = append(out, m)
	}
	return out
}

// The JSON logger redacts on its own (not only through the redacted
// standard error): the message, a value, a group, a secret-named key.
func TestJSONLogsAreRedacted(t *testing.T) {
	var raw bytes.Buffer // not a redacting writer
	log := newLogger(&raw, globals{logFormat: "json", debug: true})
	log.With("password", "hunter2-not-real").WithGroup("input").Info("read "+ghToken, "path", "/tmp/"+ghToken+"/plan.json", "count", 3)
	out := raw.String()
	if strings.Contains(out, ghToken) || strings.Contains(out, "hunter2-not-real") || !strings.Contains(out, "[REDACTED:github-token]") {
		t.Fatalf("a secret reached the log: %s", out)
	}
	lines := jsonLines(t, out)
	if len(lines) != 1 || lines[0]["level"] != "INFO" {
		t.Fatalf("lines %v", lines)
	}
}

// Through the CLI: --log-format json --debug writes JSON lines to standard
// error, every one redacted, and the report on standard output is
// unchanged (the logs never mix into it); without --debug, only warnings.
func TestCLIJSONLogs(t *testing.T) {
	root := filepath.Join(t.TempDir(), ghToken)
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := RunWith(context.Background(), []string{"--log-format", "json", "scan", "--debug", "--root", root, "--format", "json"}, &out, &errOut, DefaultEnv())
	if code != ExitIncomplete {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	lines := jsonLines(t, errOut.String())
	msgs := map[string]bool{}
	for _, l := range lines {
		if m, ok := l["msg"].(string); ok {
			msgs[m] = true
		}
	}
	if !msgs["inputs loaded"] || !msgs["analysis"] || strings.Contains(errOut.String(), ghToken) || !strings.Contains(errOut.String(), "[REDACTED:github-token]") {
		t.Fatalf("logs: %s", errOut.String())
	}
	if !json.Valid(out.Bytes()) {
		t.Fatal("the report on standard output is not JSON alone")
	}
	errOut.Reset()
	_ = RunWith(context.Background(), []string{"scan", "--root", root}, &bytes.Buffer{}, &errOut, DefaultEnv())
	if strings.Contains(errOut.String(), "inputs loaded") {
		t.Errorf("debug records without --debug: %s", errOut.String())
	}
}

// --log-format takes text or json; the globals go anywhere before "--".
func TestGlobalFlags(t *testing.T) {
	rest, g, err := splitGlobals([]string{"scan", "--log-format=json", "--root", "x", "--debug", "--", "--debug"})
	if err != nil || !g.debug || g.logFormat != "json" || strings.Join(rest, " ") != "scan --root x -- --debug" {
		t.Fatalf("%v %+v %v", err, g, rest)
	}
	for _, bad := range [][]string{{"--log-format", "xml", "version"}, {"version", "--log-format"}} {
		if code, _, errOut := run(t, bad...); code != ExitUsage || !strings.Contains(errOut, "--log-format is text or json") {
			t.Errorf("%v: %d %q", bad, code, errOut)
		}
	}
}

// A panic is one line; with --debug, the stack trace follows; both are
// redacted.
func TestCrash(t *testing.T) {
	var b bytes.Buffer
	Crash(&b, []string{"scan"}, "boom "+ghToken)
	if strings.Contains(b.String(), ghToken) || strings.Contains(b.String(), "goroutine") || !strings.Contains(b.String(), "run again with --debug") {
		t.Fatalf("%q", b.String())
	}
	b.Reset()
	Crash(&b, []string{"scan", "--debug"}, "boom")
	if !strings.Contains(b.String(), "goroutine ") || !strings.Contains(b.String(), "runtime/debug.Stack") {
		t.Fatalf("no stack trace: %q", b.String())
	}
}
