package app

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/r3oof-900/clapa/internal/config"
	"github.com/r3oof-900/clapa/internal/safeio"
)

// LoadConfig reads clapa.yaml from the scan root (rel "" or a missing
// default file gives the default configuration).
func LoadConfig(root, rel string, required bool) (*config.Config, error) {
	if rel == "" {
		rel = "clapa.yaml"
	}
	data, err := safeio.ReadFile(root, rel, safeio.DefaultLimits())
	switch {
	case err == nil:
		return config.Parse(data)
	case !required && errors.Is(err, fs.ErrNotExist):
		return config.Default(), nil
	}
	return nil, fmt.Errorf("%w: %w", config.ErrInvalid, err)
}

// ErrOutput is returned when the output path is unsafe.
var ErrOutput = errors.New("app: unsafe output path")

// CreateOutput opens a report file for writing. It refuses a path that is a
// symlink or not a regular file, so a report cannot be redirected onto
// another file (docs/THREAT_MODEL.md).
func CreateOutput(path string) (io.WriteCloser, error) {
	clean := filepath.Clean(path)
	if info, err := os.Lstat(clean); err == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrOutput, path)
	}
	f, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrOutput, err)
	}
	return f, nil
}

// DefaultLimits are the input limits of a scan.
func DefaultLimits() safeio.Limits { return safeio.DefaultLimits() }
