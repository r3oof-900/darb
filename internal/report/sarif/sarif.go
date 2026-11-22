// Package sarif writes the report as SARIF 2.1.0 (OASIS), for code-scanning
// tools. Each finding is a result; its fingerprint is the result's partial
// fingerprint, so a moved line keeps the alert. An attack path is the
// result's code flow, one location per hop; file locations are relative to
// %SRCROOT%, the scan root.
package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/r3oof-900/clapa/pkg/schema"
)

// SARIF 2.1.0 schema location.
const schemaURI = "https://json.schemastore.org/sarif-2.1.0.json"

// Reporter writes SARIF.
type Reporter struct{}

type log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []rule `json:"rules"`
}

type message struct {
	Text string `json:"text"`
}

type rule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription message        `json:"shortDescription"`
	FullDescription  message        `json:"fullDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             message           `json:"message"`
	Locations           []location        `json:"locations,omitempty"`
	CodeFlows           []codeFlow        `json:"codeFlows,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type codeFlow struct {
	ThreadFlows []threadFlow `json:"threadFlows"`
}

type threadFlow struct {
	Locations []threadFlowLocation `json:"locations"`
}

type threadFlowLocation struct {
	Location location `json:"location"`
}

type location struct {
	Message          *message  `json:"message,omitempty"`
	PhysicalLocation *physical `json:"physicalLocation,omitempty"`
	LogicalLocations []logical `json:"logicalLocations,omitempty"`
}

type physical struct {
	ArtifactLocation artifact `json:"artifactLocation"`
	Region           *region  `json:"region,omitempty"`
}

type artifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// srcRoot is the base of every file location: the scan root (--root).
const srcRoot = "%SRCROOT%"

type region struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

type logical struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
}

// level maps severities to SARIF levels.
func level(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	}
	return "note"
}

// Write renders r.
func (Reporter) Write(w io.Writer, r *schema.Report) error {
	d := driver{Name: r.Tool.Name, Version: r.Tool.Version, InformationURI: r.Tool.InformationURI, Rules: []rule{}}
	for i := range r.Rules {
		ru := &r.Rules[i]
		help := ""
		if len(ru.References) > 0 {
			help = ru.References[0]
		}
		d.Rules = append(d.Rules, rule{
			ID: ru.ID, Name: ru.ID, ShortDescription: message{ru.Title}, FullDescription: message{ru.Rationale}, HelpURI: help,
			Properties: map[string]any{"tags": append([]string{"security", ru.Kind}, ru.Techniques...), "version": ru.Version},
		})
	}
	results := []result{}
	for i := range r.Findings {
		results = append(results, convert(&r.Findings[i]))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	// %SRCROOT% is left to the consumer (code scanning maps it to the
	// checkout), so the report names no local directory.
	return enc.Encode(log{Schema: schemaURI, Version: "2.1.0", Runs: []run{{Tool: tool{Driver: d}, Results: results}}})
}

func convert(f *schema.Finding) result {
	text := f.Title
	switch {
	case f.Resource != "":
		text += ": " + f.Resource
	case f.Entry != "":
		text += fmt.Sprintf(": %s -> %s via %s", f.Entry, f.Jewel, strings.Join(f.Path, ", "))
	}
	if len(f.Chokepoints) > 0 {
		text += ". Cheapest fix: " + strings.Join(f.Chokepoints, "; ")
	}
	if !f.Confirmed {
		text += " (unconfirmed: depends on values that are not known)"
	}
	res := result{
		RuleID: f.Rule, Level: level(f.Severity), Message: message{text},
		PartialFingerprints: map[string]string{"clapaFingerprint/v1": f.Fingerprint},
		Properties: map[string]any{
			"severity": f.Severity, "score": f.Score, "confirmed": f.Confirmed, "confidence": f.Confidence,
			"security-severity": fmt.Sprintf("%.1f", float64(f.Score)/100),
		},
	}
	if l := f.Location; l != nil {
		loc := location{}
		if l.File != "" {
			loc.PhysicalLocation = &physical{ArtifactLocation: artifact{URI: l.File, URIBaseID: srcRoot}}
			if l.StartLine > 0 {
				loc.PhysicalLocation.Region = &region{StartLine: l.StartLine, EndLine: l.EndLine}
			}
		}
		if name := strings.TrimSpace(l.Address + " " + l.ARN); name != "" {
			loc.LogicalLocations = []logical{{FullyQualifiedName: name}}
		}
		res.Locations = []location{loc}
	}
	res.CodeFlows = flow(f, res.Locations)
	return res
}

// flow is the attack path as a code flow: the entry (at the finding's
// location), then one location per hop, named by the node it reaches.
func flow(f *schema.Finding, at []location) []codeFlow {
	if len(f.Hops) == 0 {
		return nil
	}
	first := location{Message: &message{"entry " + f.Entry}, LogicalLocations: []logical{{FullyQualifiedName: f.Entry}}}
	if len(at) > 0 {
		first.PhysicalLocation = at[0].PhysicalLocation
	}
	locs := []threadFlowLocation{{Location: first}}
	for _, h := range f.Hops {
		locs = append(locs, threadFlowLocation{Location: location{
			Message:          &message{h.Kind + " " + h.From + " -> " + h.To},
			LogicalLocations: []logical{{FullyQualifiedName: h.To}},
		}})
	}
	return []codeFlow{{ThreadFlows: []threadFlow{{Locations: locs}}}}
}
