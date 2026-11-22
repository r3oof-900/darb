package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/r3oof-900/clapa/internal/llm"
	"github.com/r3oof-900/clapa/internal/llm/claude"
	"github.com/r3oof-900/clapa/internal/llm/pseudonymize"
	"github.com/r3oof-900/clapa/pkg/schema"
)

// LLMOptions select the explanation provider of scan --llm and explain
// (DESIGN.md §10). Provider "" is none: template text only.
type LLMOptions struct {
	Provider string
	Model    string
	APIKey   string // from ANTHROPIC_API_KEY only; never printed or reported
	// RedactIdentifiers: --llm-redact-identifiers.
	RedactIdentifiers bool
}

// Explainer is an explanation provider.
type Explainer = llm.Explainer

// LLMProviders are the values of --llm.
func LLMProviders() []string { return []string{"anthropic"} }

// LLMKeyVariable is where the API key of --llm anthropic is read from.
const LLMKeyVariable = "ANTHROPIC_API_KEY"

// NewExplainer makes the provider o names (nil, nil: none).
func NewExplainer(o LLMOptions) (Explainer, error) {
	switch o.Provider {
	case "":
		return nil, nil
	case "anthropic":
		if o.APIKey == "" {
			return nil, fmt.Errorf("--llm anthropic needs the API key in %s", LLMKeyVariable)
		}
		c, err := claude.New(claude.Options{APIKey: o.APIKey, Model: o.Model})
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	return nil, fmt.Errorf("unknown --llm provider %q (known: %s)", o.Provider, strings.Join(LLMProviders(), ", "))
}

// isPath: a finding with an attack path (not a misconfiguration).
func isPath(f *schema.Finding) bool { return f.Resource == "" }

// ExplainReport explains every attack-path finding of r and writes the
// executive summary, with one pseudonym mapping for the whole report when
// redactIDs. p nil: template text, with a note. A misconfiguration is
// explained by its rule's rationale (clapa rules show), not by a provider.
func ExplainReport(ctx context.Context, r *schema.Report, p Explainer, redactIDs bool) {
	m := mapping(redactIDs)
	all := make([]llm.Evidence, 0, len(r.Findings))
	for i := range r.Findings {
		f := &r.Findings[i]
		e := llm.EvidenceOf(f)
		all = append(all, e)
		if isPath(f) {
			f.Explanation = explanationOf(new(llm.Explain(ctx, p, llm.ExplainRequest{Kind: llm.KindFinding, Findings: []llm.Evidence{e}}, m)))
		}
	}
	r.ExecutiveSummary = explanationOf(new(llm.Explain(ctx, p, llm.ExplainRequest{Kind: llm.KindSummary, Findings: all}, m)))
}

// ExplainFinding explains the finding of r with a fingerprint (or a unique
// prefix of one), of any kind, and returns it.
func ExplainFinding(ctx context.Context, r *schema.Report, fp string, p Explainer, redactIDs bool) (*schema.Finding, error) {
	var found *schema.Finding
	for i := range r.Findings {
		if strings.HasPrefix(r.Findings[i].Fingerprint, fp) {
			if found != nil {
				return nil, fmt.Errorf("fingerprint prefix %q matches more than one finding", fp)
			}
			found = &r.Findings[i]
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no finding has fingerprint %q", fp)
	}
	req := llm.ExplainRequest{Kind: llm.KindFinding, Findings: []llm.Evidence{llm.EvidenceOf(found)}}
	found.Explanation = explanationOf(new(llm.Explain(ctx, p, req, mapping(redactIDs))))
	return found, nil
}

func mapping(redactIDs bool) *pseudonymize.Mapping {
	if redactIDs {
		return pseudonymize.New()
	}
	return nil
}

func explanationOf(e *llm.Explanation) *schema.Explanation {
	return &schema.Explanation{Summary: e.Summary, Attack: e.Attack, Fix: e.Fix, AIGenerated: e.AIGenerated, Model: e.Model, Note: e.Note}
}
