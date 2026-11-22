// Package redact detects and redacts secrets in strings: everything the CLI
// writes to standard error, any structured log (Handler), and every string of
// LLM-bound evidence (DESIGN.md section 10). Implemented in Phase 7.
package redact
