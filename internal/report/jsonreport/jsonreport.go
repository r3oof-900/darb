// Package jsonreport writes the report document as indented JSON
// (schema darb-report/v1).
package jsonreport

import (
	"encoding/json"
	"io"

	"github.com/r3oof-900/darb/pkg/schema"
)

// Reporter writes JSON.
type Reporter struct{}

// Write renders r.
func (Reporter) Write(w io.Writer, r *schema.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
