// Command archgen regenerates the parts of .golangci.yml and docs/DESIGN.md
// that are derived from the layer table in internal/archtest/layers.go.
//
// Usage (from the module root): go run ./tools/archgen
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/r3oof-900/darb/internal/archtest"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "archgen:", err)
		os.Exit(1)
	}
}

func run() error {
	dir := flag.String("root", ".", "directory inside the module")
	flag.Parse()
	root, err := archtest.FindModuleRoot(*dir)
	if err != nil {
		return err
	}
	rules := archtest.Rules()
	edits := []struct {
		file    string
		regions map[string]string
	}{
		{".golangci.yml", map[string]string{
			archtest.RegionDepguard:  archtest.RenderDepguard(rules),
			archtest.RegionCorePaths: archtest.RenderCorePaths(rules),
		}},
		{"docs/DESIGN.md", map[string]string{archtest.RegionLayerDoc: archtest.RenderLayerDoc(rules)}},
	}
	for _, e := range edits {
		if err := rewrite(filepath.Join(root, filepath.FromSlash(e.file)), e.regions); err != nil {
			return err
		}
	}
	return nil
}

func rewrite(path string, regions map[string]string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a fixed repository file joined to the module root.
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	for _, name := range []string{archtest.RegionDepguard, archtest.RegionCorePaths, archtest.RegionLayerDoc} {
		body, ok := regions[name]
		if !ok {
			continue
		}
		if text, err = archtest.ReplaceRegion(text, name, body); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	//nolint:gosec // G703: developer tool; path is the module root joined with a fixed repository file name.
	if err := os.WriteFile(path, []byte(text), info.Mode().Perm()); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
