package schema

// Version of the report document. Consumers check it; fields are only
// added within a major version.
const Version = "clapa-report/v1"

// Report is the document every output format renders.
type Report struct {
	Schema         string           `json:"schema"`
	Tool           Tool             `json:"tool"`
	ThreatModel    ThreatModel      `json:"threat_model"`
	Summary        Summary          `json:"summary"`
	Findings       []Finding        `json:"findings"`
	IntendedAccess []IntendedAccess `json:"intended_access"`
	Coverage       Coverage         `json:"coverage"`
	Graph          Graph            `json:"graph"`
	Rules          []Rule           `json:"rules"`
	// Suppressed, ExpiredSuppressions: .clapa-ignore.yaml (--ignore);
	// Baseline: the comparison with --baseline. Absent when not used.
	Suppressed          []SuppressedFinding  `json:"suppressed,omitempty"`
	ExpiredSuppressions []ExpiredSuppression `json:"expired_suppressions,omitempty"`
	Baseline            *Baseline            `json:"baseline,omitempty"`
	ExitCode            int                  `json:"exit_code"`
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
	// AlternativeFixDetail: the cheapest fix of each alternative_fix edge.
	AlternativeFixDetail []FixStep `json:"alternative_fix_detail,omitempty"`
	// SharedFixPossible: resources one change to whose policy breaks two or
	// more chokepoint edges; cut_cost then overstates the fix.
	SharedFixPossible []string  `json:"shared_fix_possible,omitempty"`
	DefaultsUsed      []Default `json:"defaults_used"`
	Evidence          []string  `json:"evidence,omitempty"`
	Location          *Location `json:"location,omitempty"`
	Fingerprint       string    `json:"fingerprint"`
}

// FixStep is one change that breaks one edge.
type FixStep struct {
	Edge string `json:"edge"`
	Side string `json:"side"`
	// Kind: "narrow" (make a broad grant specific) or "revoke" (remove an
	// explicit grant; confirm it is not needed), SCORING.md §4.1.
	Kind   string `json:"fix_kind"`
	Policy string `json:"policy"`
	Cost   int64  `json:"cost"`
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
