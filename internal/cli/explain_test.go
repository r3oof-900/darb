package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/r3oof-900/clapa/internal/app"
	"github.com/r3oof-900/clapa/internal/llm"
)

// fakeLLM records what it is sent and answers with the identifiers it got
// (tokens, with --llm-redact-identifiers), so the test sees them restored.
type fakeLLM struct {
	mu   sync.Mutex
	sent []string
	fail bool
}

func (f *fakeLLM) Explain(_ context.Context, r llm.ExplainRequest) (llm.Explanation, error) {
	b, _ := json.Marshal(r)
	f.mu.Lock()
	f.sent = append(f.sent, string(b))
	f.mu.Unlock()
	if f.fail {
		return llm.Explanation{}, context.DeadlineExceeded
	}
	e := r.Findings[0]
	return llm.Explanation{Summary: "<script>alert(1)</script> " + e.Jewel, Attack: "from " + e.Entry, Fix: "cut it"}, nil
}
func (*fakeLLM) Model() string { return "fake-model" }

// The secret is a test value: it must never be printed.
const testKey = "sk-ant-api03-" + "TESTKEYTESTKEYTESTKEYTESTKEYTESTKEYTESTKEY"

func runLLM(t *testing.T, fake *fakeLLM, key string, args ...string) (code ExitCode, stdout, stderr string, got app.LLMOptions) {
	t.Helper()
	env := &Env{
		Getenv: func(k string) string {
			if k == app.LLMKeyVariable {
				return key
			}
			return ""
		},
		Explainer: func(o app.LLMOptions) (app.Explainer, error) {
			got = o
			if o.Provider == "" {
				return nil, nil
			}
			if o.APIKey == "" || o.Provider != "anthropic" {
				return app.NewExplainer(o) // the real checks: no key, unknown provider
			}
			return fake, nil
		},
	}
	var out, errOut bytes.Buffer
	code = RunWith(context.Background(), args, &out, &errOut, env)
	return code, out.String(), errOut.String(), got
}

var scan01 = []string{"--root", fixtures + "01_classic/vulnerable", "--terraform", "terraform", "--k8s", "k8s"}

// scan --llm: the key comes from the environment only and is never
// printed; path findings and the summary are explained and labelled.
func TestScanLLM(t *testing.T) {
	fake := &fakeLLM{}
	code, out, errOut, opts := runLLM(t, fake, testKey, append(append([]string{"scan"}, scan01...), "--llm", "anthropic", "--format", "json")...)
	if code != ExitFindings || opts.APIKey != testKey || opts.Provider != "anthropic" {
		t.Fatalf("%d %q %+v", code, errOut, opts.Provider)
	}
	if strings.Contains(out+errOut, testKey) {
		t.Fatal("the API key is printed")
	}
	var doc struct {
		ExecutiveSummary *struct {
			AIGenerated bool   `json:"ai_generated"`
			Model       string `json:"model"`
		} `json:"executive_summary"`
		Findings []struct {
			Rule        string `json:"rule"`
			Resource    string `json:"resource"`
			Jewel       string `json:"jewel"`
			Explanation *struct {
				Summary     string `json:"summary"`
				AIGenerated bool   `json:"ai_generated"`
			} `json:"explanation"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ExecutiveSummary == nil || !doc.ExecutiveSummary.AIGenerated || doc.ExecutiveSummary.Model != "fake-model" {
		t.Fatalf("summary: %+v", doc.ExecutiveSummary)
	}
	paths := 0
	for _, f := range doc.Findings {
		switch {
		case f.Resource == "" && (f.Explanation == nil || !f.Explanation.AIGenerated || !strings.HasSuffix(f.Explanation.Summary, f.Jewel)):
			t.Errorf("%s: %+v", f.Rule, f.Explanation)
		case f.Resource != "" && f.Explanation != nil:
			t.Errorf("%s: a misconfiguration is sent to the provider", f.Rule)
		case f.Resource == "":
			paths++
		}
	}
	if paths == 0 || len(fake.sent) != paths+1 {
		t.Fatalf("%d path findings, %d requests", paths, len(fake.sent))
	}
}

// --llm-redact-identifiers: no account ID or ARN leaves; the answer comes
// back with the real names.
func TestScanLLMRedactsIdentifiers(t *testing.T) {
	fake := &fakeLLM{}
	_, out, _, _ := runLLM(t, fake, testKey, append(append([]string{"scan"}, scan01...), "--llm", "anthropic", "--llm-redact-identifiers")...)
	for _, s := range fake.sent {
		if strings.Contains(s, "arn:aws") || strings.Contains(s, "111122223333") {
			t.Fatalf("an identifier was sent: %s", s)
		}
	}
	if !strings.Contains(out, "AI-generated explanation (fake-model") || !strings.Contains(out, "arn:aws:s3:::") {
		t.Fatalf("console: %s", out)
	}
}

// Usage errors: --llm without a key, an unknown provider, --llm-model
// without --llm. The message names the variable, never a value.
func TestLLMUsage(t *testing.T) {
	for name, args := range map[string][]string{
		"no key":      {"--llm", "anthropic"},
		"unknown":     {"--llm", "other"},
		"model alone": {"--llm-model", "m"},
	} {
		key := ""
		if name != "no key" {
			key = testKey
		}
		code, _, errOut, _ := runLLM(t, &fakeLLM{}, key, append(append([]string{"scan"}, scan01...), args...)...)
		if code != ExitUsage || strings.Contains(errOut, testKey) {
			t.Errorf("%s: %d %q", name, code, errOut)
		}
		if name == "no key" && !strings.Contains(errOut, app.LLMKeyVariable) {
			t.Errorf("no key: %q", errOut)
		}
	}
}

// clapa explain: without --llm the template, with a provider its answer;
// when the provider fails, the template with a note, and exit 0.
func TestExplainCommand(t *testing.T) {
	fp := pathFingerprint(t, scan01)
	args := append(append([]string{"explain"}, scan01...), fp[:12])
	code, out, errOut, _ := runLLM(t, &fakeLLM{}, "", args...)
	if code != ExitOK || !strings.Contains(out, "Explanation (template text: no LLM provider") || !strings.Contains(out, "The fix: The cheapest fix:") {
		t.Fatalf("template: %d %q %q", code, out, errOut)
	}
	code, out, _, _ = runLLM(t, &fakeLLM{}, testKey, append(args[:len(args)-1:len(args)-1], "--llm", "anthropic", "--format", "json", fp)...)
	var e struct {
		AIGenerated bool   `json:"ai_generated"`
		Attack      string `json:"attack"`
	}
	if err := json.Unmarshal([]byte(out), &e); code != ExitOK || err != nil || !e.AIGenerated || !strings.HasPrefix(e.Attack, "from k8s:") {
		t.Fatalf("provider: %d %v %q", code, err, out)
	}
	code, out, _, _ = runLLM(t, &fakeLLM{fail: true}, testKey, append(args[:len(args)-1:len(args)-1], "--llm", "anthropic", fp)...)
	if code != ExitOK || !strings.Contains(out, "the LLM explanation failed (context deadline exceeded)") {
		t.Fatalf("failure: %d %q", code, out)
	}
	if code, _, _, _ := runLLM(t, &fakeLLM{}, "", "explain", "--root", fixtures+"01_classic/vulnerable", "--terraform", "terraform", "nope"); code != ExitUsage {
		t.Errorf("unknown fingerprint: %d", code)
	}
	if code, _, _, _ := runLLM(t, &fakeLLM{}, "", "explain", "--format", "html", fp); code != ExitUsage {
		t.Errorf("html: %d", code)
	}
}

// Standard error is redacted: an argument quoted in an error keeps no
// secret.
func TestStderrIsRedacted(t *testing.T) {
	secret := "gh" + "p_" + strings.Repeat("A", 36)
	code, _, errOut := run(t, "scan", "--format", secret)
	if code != ExitUsage || strings.Contains(errOut, secret) || !strings.Contains(errOut, "[REDACTED:github-token]") {
		t.Fatalf("%d %q", code, errOut)
	}
}
