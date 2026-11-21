package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"go.yaml.in/yaml/v3"
)

// tools/depage/allow.yaml lets a requirement younger than the minimum age
// in, for one reason only: the newer release fixes a vulnerability.
//
//   - module: golang.org/x/net
//     version: v0.63.0
//     reason: fixes the HTTP/2 rapid reset in the version before
//     advisory: GO-2026-1234        # or CVE-2026-12345
//     expires: 2026-12-05           # the exception ends; the check blocks again
//
// Every field is required; an entry without its reason, its advisory or its
// expiry date, or with a malformed one, rejects the whole file (exit 2).
// An entry allows exactly that module at exactly that version, and only
// before its expiry date (compared with --at).
type allowEntry struct {
	Module   string `yaml:"module"`
	Version  string `yaml:"version"`
	Reason   string `yaml:"reason"`
	Advisory string `yaml:"advisory"`
	Expires  string `yaml:"expires"`
	expires  time.Time
}

var (
	advisoryRE  = regexp.MustCompile(`^(GO-\d{4}-\d{4,}|CVE-\d{4}-\d{4,})$`)
	errAllow    = errors.New("invalid allow file")
	errNoReason = errors.New("reason is required")
)

// loadAllow reads the allow file; a missing file allows nothing.
func loadAllow(path string) ([]allowEntry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the operator's allow file.
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var entries []allowEntry
	if err := dec.Decode(&entries); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w %s: %w", errAllow, path, err)
	}
	for i := range entries {
		if err := entries[i].validate(); err != nil {
			return nil, fmt.Errorf("%w %s: entry %d (%s %s): %w", errAllow, path, i+1, entries[i].Module, entries[i].Version, err)
		}
	}
	return entries, nil
}

func (e *allowEntry) validate() error {
	switch {
	case e.Module == "" || e.Version == "":
		return errors.New("module and version are required")
	case e.Reason == "":
		return errNoReason
	case e.Advisory == "":
		return errors.New("advisory is required (GO-yyyy-nnnn or CVE-yyyy-nnnnn)")
	case !advisoryRE.MatchString(e.Advisory):
		return fmt.Errorf("advisory %q is not GO-yyyy-nnnn or CVE-yyyy-nnnnn", e.Advisory)
	case e.Expires == "":
		return errors.New("expires is required (yyyy-mm-dd)")
	}
	t, err := time.Parse(time.DateOnly, e.Expires)
	if err != nil {
		return fmt.Errorf("expires %q is not yyyy-mm-dd", e.Expires)
	}
	e.expires = t
	return nil
}

// allowed returns the entry for path@version, and whether it is still in
// force at ref; nil when there is none.
func allowed(entries []allowEntry, path, version string, ref time.Time) (*allowEntry, bool) {
	for i := range entries {
		if e := &entries[i]; e.Module == path && e.Version == version {
			return e, ref.Before(e.expires)
		}
	}
	return nil, false
}
