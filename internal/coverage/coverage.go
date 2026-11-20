package coverage

import (
	"cmp"
	"slices"
	"strings"
)

// Kind classifies a coverage gap.
type Kind string

// Gap kinds. Every gap means "CLAPA could not see or decide something";
// none of them is ever reported as safe.
const (
	// KindUnresolved: a static value (variable, local, expression) was not resolved.
	KindUnresolved Kind = "unresolved"
	// KindUnknownAfterApply: a plan value is only known after apply.
	KindUnknownAfterApply Kind = "unknown-after-apply"
	// KindParseError: an input file could not be parsed.
	KindParseError Kind = "parse-error"
	// KindUnsupported: an input kind, field or construct is not supported.
	KindUnsupported Kind = "unsupported"
	// KindNotModelled: an AWS feature that can grant access is not evaluated (e.g. KMS grants).
	KindNotModelled Kind = "not-modelled"
	// KindAccessDenied, KindThrottled, KindTimeout, KindAPIError: live or snapshot API failures.
	KindAccessDenied Kind = "access-denied"
	KindThrottled    Kind = "throttled"
	KindTimeout      Kind = "timeout"
	KindAPIError     Kind = "api-error"
)

// Gap is one thing the scan could not cover.
type Gap struct {
	Kind    Kind
	Source  string // collector name, e.g. "terraform-hcl"
	File    string // slash-separated, relative to the scan root
	Line    int
	Address string // Terraform address, K8s object, or ARN
	Service string
	Region  string
	Account string
	API     string
	Detail  string
}

// Recorder collects gaps. The zero value is ready to use. It is not safe for
// concurrent use; concurrent collectors each use their own and Merge.
type Recorder struct {
	gaps []Gap
}

// Add records a gap.
func (r *Recorder) Add(g *Gap) { r.gaps = append(r.gaps, *g) }

// Merge appends all gaps of o.
func (r *Recorder) Merge(o *Recorder) { r.gaps = append(r.gaps, o.gaps...) }

// Len returns the number of gaps.
func (r *Recorder) Len() int { return len(r.gaps) }

// Count returns the number of gaps of kind k.
func (r *Recorder) Count(k Kind) int {
	n := 0
	for i := range r.gaps {
		if r.gaps[i].Kind == k {
			n++
		}
	}
	return n
}

// Gaps returns a sorted, de-duplicated copy of the gaps.
func (r *Recorder) Gaps() []Gap {
	ptrs := make([]*Gap, len(r.gaps))
	for i := range r.gaps {
		ptrs[i] = &r.gaps[i]
	}
	slices.SortFunc(ptrs, compareGaps)
	ptrs = slices.CompactFunc(ptrs, func(a, b *Gap) bool { return *a == *b })
	out := make([]Gap, len(ptrs))
	for i, p := range ptrs {
		out[i] = *p
	}
	return out
}

func compareGaps(a, b *Gap) int {
	return cmp.Or(
		strings.Compare(a.Source, b.Source), strings.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line),
		strings.Compare(a.Address, b.Address), strings.Compare(string(a.Kind), string(b.Kind)),
		strings.Compare(a.Account, b.Account), strings.Compare(a.Region, b.Region),
		strings.Compare(a.Service, b.Service), strings.Compare(a.API, b.API), strings.Compare(a.Detail, b.Detail),
	)
}
