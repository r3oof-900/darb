package schema

// Version of the report document. Consumers check it; fields are only
// added within a major version.
const Version = "darb-report/v1"

// Report is the document every output format renders.
type Report struct {
	Schema string `json:"schema"`
	Tool   Tool   `json:"tool"`
	// GeneratedAt: when the report was made (RFC 3339, UTC); only with
	// --timestamps, so that two scans of the same input are identical.
	GeneratedAt string `json:"generated_at,omitempty"`
	// Inputs: what was scanned, each with a digest.
	Inputs []ScannedInput `json:"inputs,omitempty"`
	// ExecutiveSummary: with scan --llm, the report in a few sentences.
	ExecutiveSummary *Explanation     `json:"executive_summary,omitempty"`
	ThreatModel      ThreatModel      `json:"threat_model"`
	Summary          Summary          `json:"summary"`
	Findings         []Finding        `json:"findings"`
	IntendedAccess   []IntendedAccess `json:"intended_access"`
	Coverage         Coverage         `json:"coverage"`
	Graph            Graph            `json:"graph"`
	Rules            []Rule           `json:"rules"`
	// Suppressed, ExpiredSuppressions: .darb-ignore.yaml (--ignore);
	// Baseline: the comparison with --baseline. Absent when not used.
	Suppressed          []SuppressedFinding  `json:"suppressed,omitempty"`
	ExpiredSuppressions []ExpiredSuppression `json:"expired_suppressions,omitempty"`
	Baseline            *Baseline            `json:"baseline,omitempty"`
	ExitCode            int                  `json:"exit_code"`
}

// ScannedInput is one input of the scan: a path under the scan root (a
// Terraform directory or plan, a manifest directory, an AWS snapshot) or a
// live source (AWS accounts and regions, a cluster by its key), and the
// SHA-256 of what was read: the files (path, length and content of each, in
// order) or, for a live source, the collected data as JSON.
type ScannedInput struct {
	Kind     string   `json:"kind"`
	Path     string   `json:"path,omitempty"`
	Cluster  string   `json:"cluster,omitempty"`
	Accounts []string `json:"accounts,omitempty"`
	Regions  []string `json:"regions,omitempty"`
	Digest   string   `json:"digest"`
}

// Remediation is the verified remediation of a finding (scan --fixes):
// its fixes in output order (DESIGN.md §9.2: a verified root-cause fix
// first; otherwise the mitigation, then the root cause as a suggestion,
// and Note), the resolve steps to run first, what would decide an
// unconfirmed path.
type Remediation struct {
	Fixes   []Fix    `json:"fixes"`
	Note    string   `json:"note,omitempty"`
	Pending []string `json:"pending,omitempty"`
	Missing []string `json:"missing,omitempty"`
	NoFix   bool     `json:"no_fix_within_constraints,omitempty"`
}

// Fix is one strategy: its changes, both verifications and the patch.
type Fix struct {
	// Strategy: "root-cause" (narrows or removes the grant) or "mitigation"
	// (blocks this path only; the broad grant remains).
	Strategy   string   `json:"fix_strategy"`
	Suggestion string   `json:"suggestion,omitempty"`
	Changes    []Change `json:"changes"`
	// VerifiedInMemory: level 1, the change applied to the model;
	// VerifiedOnFiles: level 2, the patched files rescanned from scratch.
	VerifiedInMemory bool     `json:"verified_in_memory"`
	VerifiedOnFiles  bool     `json:"verified_on_patched_files"`
	Reasons          []string `json:"reasons,omitempty"`
	// Pending: only the known steps are verified (resolve steps first).
	Pending  string   `json:"pending,omitempty"`
	Diff     string   `json:"diff,omitempty"`
	TODO     []string `json:"todo,omitempty"`
	Policies []Policy `json:"policies,omitempty"`
}

// Change breaks one edge.
type Change struct {
	Edge string `json:"edge"`
	Side string `json:"side"`
	Kind string `json:"fix_kind"`
	Cost int64  `json:"cost"`
	Why  string `json:"why,omitempty"`
	TODO string `json:"todo,omitempty"`
}

// Policy is a changed snapshot or live policy document, as JSON.
type Policy struct {
	ID       string `json:"id"`
	Note     string `json:"note,omitempty"`
	Document string `json:"document,omitempty"`
}

// Tool identifies the build and the rule catalog.
type Tool struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	RuleCatalog    string `json:"rule_catalog_version"`
	InformationURI string `json:"information_uri"`
}

// ThreatModel states which model the scan used.
type ThreatModel struct {
	AssumeCompromised bool   `json:"assume_compromised"`
	FailOn            string `json:"fail_on"`
}

// Summary counts findings by severity.
type Summary struct {
	Findings    int            `json:"findings"`
	BySeverity  map[string]int `json:"by_severity"`
	Unconfirmed int            `json:"unconfirmed"`
	// ConfirmedUnlessDenied counts the findings whose only UNKNOWNs are
	// possible Denies; Unconfirmed those that need an unknown allow.
	ConfirmedUnlessDenied int `json:"confirmed_unless_denied"`
}

// Location points at source: a file and lines, or an ARN and API call.
type Location struct {
	File      string `json:"file,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Address   string `json:"address,omitempty"`
	ARN       string `json:"arn,omitempty"`
	API       string `json:"api,omitempty"`
}

// Factors are a finding's score and every factor behind it (SCORING.md).
type Factors struct {
	Exposure       int `json:"exposure,omitempty"`
	Hops           int `json:"hops,omitempty"`
	Preconditions  int `json:"preconditions,omitempty"`
	Confidence     int `json:"confidence"`
	Likelihood     int `json:"likelihood,omitempty"`
	Classification int `json:"classification,omitempty"`
	BlastRadius    int `json:"blast_radius,omitempty"`
	Impact         int `json:"impact,omitempty"`
}

// Finding is one result.
type Finding struct {
	Rule        string  `json:"rule"`
	RuleVersion string  `json:"rule_version"`
	Kind        string  `json:"kind"`
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	Score       int     `json:"score"`
	Factors     Factors `json:"factors"`
	Confirmed   bool    `json:"confirmed"`
	// Status: "confirmed", "confirmed_unless_denied" or "unconfirmed"
	// (DESIGN.md 6.2). The severity is the worst case whatever the status.
	Status     string `json:"status"`
	Confidence string `json:"confidence"`
	// Undecided: for an unconfirmed path, what would decide it.
	Undecided      []string `json:"undecided,omitempty"`
	Entry          string   `json:"entry,omitempty"`
	Jewel          string   `json:"jewel,omitempty"`
	Resource       string   `json:"resource,omitempty"`
	Path           []string `json:"path,omitempty"`
	PathsFound     int      `json:"paths_found,omitempty"`
	PathsTruncated bool     `json:"paths_truncated,omitempty"`
	Chokepoints    []string `json:"chokepoints,omitempty"`
	CutCost        int64    `json:"cut_cost,omitempty"`
	NoFix          bool     `json:"no_fix_within_constraints,omitempty"`
	AlternativeFix []string `json:"alternative_fix,omitempty"`
	// Fix: the side of each chokepoint edge the cut chose (its cheapest fix);
	// OtherSideFix: the other sides that also break it.
	Fix          []FixStep `json:"fix,omitempty"`
	OtherSideFix []FixStep `json:"other_side_fix,omitempty"`
	// AlternativeFix: the cheapest complete cut sharing no edge with the
	// chosen one (SCORING.md §4.3); AlternativeFixDetail: its steps.
	AlternativeFixDetail []FixStep `json:"alternative_fix_detail,omitempty"`
	// SharedFixPossible: resources or policies one change to which breaks
	// two or more chokepoint edges.
	SharedFixPossible []string `json:"shared_fix_possible,omitempty"`
	// WorstCasePath: a less certain path of the same rule that scores
	// higher than Path (the severity is its score).
	WorstCasePath []string `json:"worst_case_path,omitempty"`
	// Hops, WorstCaseHops: path and worst_case_path as edges with both
	// ends and their node kinds; cut is "cut" when the cheapest fix
	// changes that edge, "resolve" when it only resolves unknowns on it.
	Hops          []Hop `json:"hops,omitempty"`
	WorstCaseHops []Hop `json:"worst_case_hops,omitempty"`
	// Branches: cut edges that are not on path (an escalation of a
	// dominated path, merged into this cut), each followed by the edge from
	// its target to the jewel when there is one.
	Branches [][]Hop `json:"branches,omitempty"`
	// AlsoFixes: path findings of other rules the cut also fixes; Uncuttable:
	// underlying edges of a cut derived read no change breaks (both stated
	// for every path finding).
	AlsoFixes  *[]FindingRef     `json:"also_fixes,omitempty"`
	Uncuttable *[]UncuttableEdge `json:"uncuttable,omitempty"`
	// RemediationStatus: "complete", or "partial_pending_resolution" when the
	// cut has a resolve step (decide the unknowns, then rescan).
	RemediationStatus string    `json:"remediation_status,omitempty"`
	DefaultsUsed      []Default `json:"defaults_used"`
	Evidence          []string  `json:"evidence,omitempty"`
	Location          *Location `json:"location,omitempty"`
	Fingerprint       string    `json:"fingerprint"`
	// Remediation: with scan --fixes, the finding's verified fixes.
	Remediation *Remediation `json:"remediation,omitempty"`
	// Explanation: with scan --llm, the finding in plain words (or the
	// template when the provider failed; Note says so).
	Explanation *Explanation `json:"explanation,omitempty"`
}

// Explanation is a finding (or the report) in plain words: what it is, how
// an attacker uses it, what the fix does. AIGenerated: written by an LLM
// provider (Model); it never changes a verdict, a score or a fix
// (DESIGN.md §10).
type Explanation struct {
	Summary     string `json:"summary"`
	Attack      string `json:"attack,omitempty"`
	Fix         string `json:"fix,omitempty"`
	AIGenerated bool   `json:"ai_generated"`
	Model       string `json:"model,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Label is how every report heads an explanation: an AI-generated one is
// marked as such.
func (e *Explanation) Label() string {
	if e.AIGenerated {
		return "AI-generated explanation (" + e.Model + "; it does not change the verdict, the score or the fix)"
	}
	return "Template explanation, not AI-generated (" + e.Note + ")"
}

// FixStep is one change that breaks one edge.
type FixStep struct {
	Edge string `json:"edge"`
	Side string `json:"side"`
	// Kind: "narrow" (make a broad grant specific), "revoke" (remove an
	// explicit grant, or detach an AWS managed policy; confirm it is not
	// needed) or "resolve" (decide an unknown), SCORING.md §4.1.
	Kind   string `json:"fix_kind"`
	Policy string `json:"policy"`
	Cost   int64  `json:"cost"`
	// Resolve: for fix_kind "resolve" (an unknown to decide, cost 0, no
	// patch), the command that decides it.
	Resolve string `json:"resolve,omitempty"`
}

// Hop is one edge of a path.
type Hop struct {
	Kind     string `json:"kind"`
	From     string `json:"from"`
	To       string `json:"to"`
	FromKind string `json:"from_kind"`
	ToKind   string `json:"to_kind"`
	Cut      string `json:"cut,omitempty"`
	// Parts: what a derived read stands for (the read, the decrypt, the
	// key protecting the data), each with its own mark.
	Parts []Hop `json:"parts,omitempty"`
}

// FindingRef names a path finding.
type FindingRef struct {
	Rule  string `json:"rule"`
	Entry string `json:"entry"`
	Jewel string `json:"jewel"`
}

// UncuttableEdge is an underlying edge no single change breaks.
type UncuttableEdge struct {
	Edge   string `json:"edge"`
	Reason string `json:"reason"`
}

// Default is a documented default a finding relies on (value_source: default).
type Default struct {
	Key         string `json:"key"`
	Setting     string `json:"setting"`
	Value       string `json:"value"`
	ValueSource string `json:"value_source"`
	Reference   string `json:"reference"`
}

// IntendedAccess is the verification of a declared intended access.
type IntendedAccess struct {
	Principal string `json:"principal"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
}

// Coverage says what the scan saw and what it could not decide.
type Coverage struct {
	Collected         int    `json:"collected"`
	GapsOverTolerance int    `json:"gaps_over_tolerance"`
	Gaps              []Gap  `json:"gaps"`
	Notes             []Note `json:"notes"`
}

// Gap is something the scan could not read or decide.
type Gap struct {
	Kind    string `json:"kind"`
	Source  string `json:"source"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	Address string `json:"address,omitempty"`
	Account string `json:"account,omitempty"`
	API     string `json:"api,omitempty"`
	Detail  string `json:"detail"`
}

// Note is a coverage note from the analysis (e.g. protected data outside
// the input).
type Note struct {
	// Kind: NoteManagedPolicies, NoteServiceCoverage and NoteInsecureTLS are
	// warnings the console prints; the others ("not-modelled", ...) are listed
	// in the JSON report.
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
}

// Note kinds the console prints as warnings.
const (
	// NoteManagedPolicies: AWS managed policies missing from the vendored
	// snapshot (their grants are unknown).
	NoteManagedPolicies = "managed-policy-snapshot"
	// NoteServiceCoverage: a service and region whose collection is
	// incomplete or whose size is unknown.
	NoteServiceCoverage = "service-coverage"
	// NoteInsecureTLS: a live cluster was read without TLS verification.
	NoteInsecureTLS = "insecure-tls"
)

// Graph summarises the access graph.
type Graph struct {
	Nodes int `json:"nodes"`
	Edges int `json:"edges"`
	Pairs int `json:"entry_jewel_pairs"`
}

// Rule is rule metadata, for reports that describe rules (SARIF).
type Rule struct {
	ID         string   `json:"id"`
	Version    string   `json:"version"`
	Kind       string   `json:"kind"`
	Title      string   `json:"title"`
	Rationale  string   `json:"rationale"`
	Techniques []string `json:"attack_techniques"`
	References []string `json:"references"`
}
