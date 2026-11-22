package llm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/llm/pseudonymize"
	"github.com/r3oof-900/darb/pkg/schema"
)

type stub struct {
	got  ExplainRequest
	resp Explanation
	err  error
}

func (s *stub) Explain(_ context.Context, r ExplainRequest) (Explanation, error) {
	s.got = r
	return s.resp, s.err
}
func (s *stub) Model() string { return "stub-model" }

func finding() *schema.Finding {
	return &schema.Finding{
		Rule: "DARB-PATH-001", Title: "A workload can read crown-jewel data", Severity: "medium", Score: 291, Status: "unconfirmed",
		Entry: "k8s:arn:aws:eks:us-east-1:111122223333:cluster/prod/apps/Deployment/app", Jewel: "arn:aws:s3:::acme-customer-pii",
		Path:         []string{"RUNS_AS x", "ASSUMES arn:aws:iam::111122223333:role/app"},
		Fix:          []schema.FixStep{{Edge: "CAN_DECRYPT role -> key", Side: "identity", Kind: "resolve", Policy: "aws_iam_role_policy.app", Resolve: "-var-file (b)"}},
		DefaultsUsed: []schema.Default{{Setting: "audience", Value: "sts.amazonaws.com"}},
	}
}

// The evidence is the report's fields; secrets are redacted and, with a
// mapping, identifiers become tokens.
func TestPrepare(t *testing.T) {
	e := EvidenceOf(finding())
	if !e.Unverified || len(e.Fix) != 1 || e.Defaults[0] != "audience = sts.amazonaws.com" {
		t.Fatalf("evidence: %+v", e)
	}
	e.Path = append(e.Path, "password = "+"Corr3ctHorse")
	p := Prepare(ExplainRequest{Kind: KindFinding, Findings: []Evidence{e}}, pseudonymize.New())
	s := strings.Join(p.Findings[0].Path, " ") + p.Findings[0].Entry + p.Findings[0].Jewel
	if strings.Contains(s, "Corr3ctHorse") || strings.Contains(s, "111122223333") || !strings.Contains(s, "[REDACTED:password-assignment]") {
		t.Fatalf("prepared: %s", s)
	}
}

// Without a provider, or when it fails, the template explains, with a note;
// the provider's answer is labelled and stripped of control characters.
func TestExplain(t *testing.T) {
	req := ExplainRequest{Kind: KindFinding, Findings: []Evidence{EvidenceOf(finding())}}
	none := Explain(t.Context(), nil, req, nil)
	if none.AIGenerated || !strings.Contains(none.Note, "no LLM provider") || !strings.Contains(none.Summary, "worst case") ||
		!strings.Contains(none.Fix, "decide aws_iam_role_policy.app (-var-file (b))") || !strings.Contains(none.Attack, "2 steps") {
		t.Errorf("template: %+v", none)
	}
	failed := Explain(t.Context(), &stub{err: errors.New("down")}, req, nil)
	if failed.AIGenerated || !strings.Contains(failed.Note, "down") {
		t.Errorf("failure: %+v", failed)
	}
	s := &stub{resp: Explanation{Summary: "fine\x1b[31m red\x07", Attack: "a\tb\nc"}}
	got := Explain(t.Context(), s, req, nil)
	if !got.AIGenerated || got.Model != "stub-model" || got.Summary != "fine[31m red" || got.Attack != "a\tb\nc" {
		t.Errorf("answer: %+v", got)
	}
	if len(s.got.Findings) != 1 || s.got.Kind != KindFinding {
		t.Errorf("the provider got %+v", s.got)
	}
	long := Explain(t.Context(), &stub{resp: Explanation{Summary: strings.Repeat("x", maxField+1)}}, req, nil)
	if long.AIGenerated {
		t.Error("an over-long answer is used")
	}
}

// The summary template counts paths and misconfigurations.
func TestSummaryTemplate(t *testing.T) {
	fs := []Evidence{EvidenceOf(finding()), {Rule: "DARB-POST-007", Severity: "low", Resource: "ns"}}
	got := Template(ExplainRequest{Kind: KindSummary, Findings: fs})
	if !strings.Contains(got.Summary, "1 attack path(s)") || !strings.Contains(got.Summary, "1 misconfiguration(s)") || !strings.Contains(got.Summary, "medium") {
		t.Errorf("summary: %+v", got)
	}
}
