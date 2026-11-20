package scoring

import (
	"math/bits"
	"strings"

	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
)

// Integer fixed point in per-mille (docs/SCORING.md): a ⊗ b = a * b / 1000,
// floor, after every multiplication, so scores are identical everywhere.

// Mul is a ⊗ b.
func Mul(a, b int) int { return a * b / 1000 }

// Factors are a path finding's score and every factor behind it.
type Factors struct {
	Exposure       int    `json:"exposure"`
	Hops           int    `json:"hops"`
	Preconditions  int    `json:"preconditions"`
	Confidence     int    `json:"confidence"`
	Likelihood     int    `json:"likelihood"`
	Classification int    `json:"classification"`
	BlastRadius    int    `json:"blast_radius"`
	Impact         int    `json:"impact"`
	Score          int    `json:"score"`
	Severity       string `json:"severity"`
}

// Hops is 1000 for one edge, then x 900 per extra edge.
func Hops(edges int) int {
	h := 1000
	for i := 1; i < edges; i++ {
		h = Mul(h, 900)
	}
	return h
}

// ConfidenceWeight is high 1000, medium 700, low 400.
func ConfidenceWeight(c graph.Confidence) int {
	switch c {
	case graph.High:
		return 1000
	case graph.Medium:
		return 700
	case graph.Low:
	}
	return 400
}

// PreconditionWeight is 900 when known satisfied, 500 when unknown.
func PreconditionWeight(p *graph.Precondition) int {
	if p.State == model.True {
		return 900
	}
	return 500
}

// Exposure of an entry point (classify.EntryPoint reason and publicness).
// An exposure whose publicness is unknown is weighted as public: an unknown
// is never scored as the safer case.
func Exposure(reason string, public model.Tri) int {
	switch {
	case reason == "anonymous":
		return 1000
	case !strings.HasPrefix(reason, "exposed:"):
		return 400 // assume-compromised
	case strings.HasSuffix(reason, "NodePort"):
		return 800
	case public == model.False:
		return 500 // internal load balancer
	}
	return 1000
}

// Classification weight of a crown jewel.
func Classification(class string) int {
	switch strings.ToLower(class) {
	case "secret", "pci", "phi":
		return 1000
	case "pii":
		return 900
	case "confidential":
		return 700
	case "internal":
		return 400
	}
	return 600 // tagged sensitive (default heuristic)
}

// BlastRadius is 1000 + 100 x floor(log2 N), capped at 1500.
func BlastRadius(jewels int) int {
	if jewels < 1 {
		jewels = 1
	}
	return min(1500, 1000+100*(bits.Len(uint(jewels))-1))
}

// Severity band of a score.
func Severity(score int) string {
	switch {
	case score >= 700:
		return "critical"
	case score >= 450:
		return "high"
	case score >= 250:
		return "medium"
	case score >= 100:
		return "low"
	}
	return "info"
}

// Path scores a path finding.
func Path(g *graph.Graph, path []graph.EdgeID, exposure, classification, jewelsFromEntry int) Factors {
	f := Factors{Exposure: exposure, Hops: Hops(len(path)), Preconditions: 1000, Confidence: 1000}
	conf := graph.High
	for _, id := range path {
		e := g.Edge(id)
		if e.Precondition != nil {
			f.Preconditions = Mul(f.Preconditions, PreconditionWeight(e.Precondition))
		}
		conf = min(conf, e.Confidence)
	}
	f.Confidence = ConfidenceWeight(conf)
	f.Likelihood = Mul(Mul(Mul(f.Exposure, f.Hops), f.Preconditions), f.Confidence)
	f.Classification = classification
	f.BlastRadius = BlastRadius(jewelsFromEntry)
	f.Impact = min(1000, Mul(f.Classification, f.BlastRadius))
	f.Score = Mul(f.Likelihood, f.Impact)
	f.Severity = Severity(f.Score)
	return f
}

// Base severities of posture rules.
const (
	BaseCritical = 850
	BaseHigh     = 600
	BaseMedium   = 350
	BaseLow      = 150
)

// Posture scores a posture finding: base ⊗ confidence.
func Posture(base int, c graph.Confidence) (score int, severity string) {
	score = Mul(base, ConfidenceWeight(c))
	return score, Severity(score)
}

// FixCost is the cost of removing an edge from one side (SCORING.md §4):
// narrowing an identity policy is cheap (it affects one principal), a
// resource policy or trust policy affects everyone who uses the resource,
// and changing a workload's identity is very expensive. -1: no such fix.
func FixCost(kind graph.Kind, sub, side string) int64 {
	switch side {
	case graph.SideIdentity:
		if kind == graph.CanEscalate {
			return 2 // remove the escalation permission
		}
		return 1 // narrow Resource (or add a condition)
	case graph.SideResource:
		return 2 // bucket policy or key policy
	case graph.SideTrust:
		return 5 // tighten the trust: sub, aud, principal, ExternalId
	case graph.SideWorkload:
		if kind == graph.CanEscalate && sub == "k8s-token" {
			return 3 // automountServiceAccountToken: false
		}
		return 100 // change the workload's identity
	case graph.SideRBAC:
		return 5
	case graph.SideMapping:
		return 8
	case graph.SideNode:
		return 3 // IMDSv2 required, hop limit 1
	}
	return -1
}
