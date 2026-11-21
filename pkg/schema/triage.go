package schema

// SuppressedFinding is a finding a .clapa-ignore.yaml suppression silences
// until its expiry date. It is not in findings and does not count for the
// exit code.
type SuppressedFinding struct {
	Fingerprint string `json:"fingerprint"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Entry       string `json:"entry,omitempty"`
	Jewel       string `json:"jewel,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Reason      string `json:"reason"`
	Owner       string `json:"owner"`
	Expires     string `json:"expires"`
}

// ExpiredSuppression is a suppression past its expiry date: its finding,
// if still present, fires again (it is in findings).
type ExpiredSuppression struct {
	Fingerprint string `json:"fingerprint"`
	Reason      string `json:"reason"`
	Owner       string `json:"owner"`
	Expires     string `json:"expires"`
	// Fires: the finding is still present and is reported again.
	Fires bool `json:"fires"`
}

// Baseline is the comparison with a previous report (--baseline): findings
// lists only the new findings, Resolved the fingerprints of the previous
// report's findings that are gone.
type Baseline struct {
	File      string         `json:"file"`
	Unchanged int            `json:"unchanged"`
	New       int            `json:"new"`
	Resolved  []ResolvedItem `json:"resolved"`
}

// ResolvedItem is a finding of the baseline that this scan no longer has.
type ResolvedItem struct {
	Fingerprint string `json:"fingerprint"`
	Rule        string `json:"rule"`
	Entry       string `json:"entry,omitempty"`
	Jewel       string `json:"jewel,omitempty"`
	Resource    string `json:"resource,omitempty"`
}
