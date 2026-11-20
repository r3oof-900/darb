package model

import "strconv"

// SourceLocation says where a piece of evidence came from: a file and line
// range (with an optional resource address), or, for live data, an ARN and
// the API call that returned it.
type SourceLocation struct {
	file      string
	startLine int
	endLine   int
	address   string
	arn       string
	api       string
}

// FileLocation is evidence from a file. address is e.g. a Terraform resource
// address or a Kubernetes "kind/namespace/name"; it may be empty.
func FileLocation(file string, startLine, endLine int, address string) SourceLocation {
	return SourceLocation{file: file, startLine: startLine, endLine: endLine, address: address}
}

// APILocation is evidence returned by a cloud API call.
func APILocation(arn, api string) SourceLocation {
	return SourceLocation{arn: arn, api: api}
}

// File returns the file path ("" for live data).
func (s *SourceLocation) File() string { return s.file }

// Lines returns the 1-based start and end lines (0 when unknown).
func (s *SourceLocation) Lines() (start, end int) { return s.startLine, s.endLine }

// Address returns the resource address within the file, if any.
func (s *SourceLocation) Address() string { return s.address }

// ARN returns the ARN of live evidence.
func (s *SourceLocation) ARN() string { return s.arn }

// API returns the API call of live evidence.
func (s *SourceLocation) API() string { return s.api }

// IsZero reports whether no location is known.
func (s *SourceLocation) IsZero() bool { return *s == SourceLocation{} }

// String renders "file:start-end (address)" or "arn via api".
func (s *SourceLocation) String() string {
	if s.file == "" {
		if s.arn == "" {
			return "<unknown location>"
		}
		return s.arn + " via " + s.api
	}
	out := s.file
	if s.startLine > 0 {
		out += ":" + strconv.Itoa(s.startLine)
		if s.endLine > s.startLine {
			out += "-" + strconv.Itoa(s.endLine)
		}
	}
	if s.address != "" {
		out += " (" + s.address + ")"
	}
	return out
}
