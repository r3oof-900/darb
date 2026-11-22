package cli

import (
	"io"

	"github.com/r3oof-900/darb/internal/redact"
)

// redacting passes everything written to standard error through the
// secret redactor (THREAT_MODEL.md: an error quoting an input never prints
// a secret in it). Messages are written whole (Fprintln), so a secret is
// never split across writes.
type redacting struct{ w io.Writer }

func (r redacting) Write(p []byte) (int, error) {
	if _, err := io.WriteString(r.w, redact.Redact(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}
