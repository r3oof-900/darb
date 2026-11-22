package cli

import (
	"flag"
	"fmt"
	"io"
	"slices"

	"github.com/r3oof-900/darb/internal/app"
)

// parseInterspersed parses flags before, between and after positional
// arguments (`darb scan . --format json`), which flag.Parse alone stops at,
// and returns the positional arguments in order. "--" ends the flags.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		if rest[0] == "--" {
			return append(positional, rest[1:]...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// addPaths turns the positional paths of scan and graph (DESIGN.md §11)
// into inputs: with one path and no --root, that path is the scan root (so
// its darb.yaml is read); each path's Terraform directories, manifest
// directories and darb snapshots are added to those the flags name.
func addPaths(f *scanFlags, paths []string, rootSet bool, stderr io.Writer) bool {
	if len(paths) == 0 {
		return true
	}
	names := slices.Clone(paths)
	if len(paths) == 1 && !rootSet {
		f.root, paths = paths[0], []string{"."}
	}
	d, err := app.DetectInputs(f.root, paths, names)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "darb:", err)
		return false
	}
	add := func(to *list, dirs []string) {
		for _, x := range dirs {
			if !slices.Contains(*to, x) {
				*to = append(*to, x)
			}
		}
	}
	add(&f.tfDirs, d.Terraform)
	add(&f.k8sDirs, d.K8s)
	add(&f.snapshots, d.Snapshots)
	return true
}

// rootGiven reports whether --root was on the command line.
func rootGiven(fs *flag.FlagSet) bool {
	given := false
	fs.Visit(func(fl *flag.Flag) { given = given || fl.Name == "root" })
	return given
}
