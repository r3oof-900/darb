package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/collect/awssnapshot"
)

// Detected are the inputs found under the paths of `darb scan PATHS...`,
// relative to the scan root, each the top-most directory of its kind (the
// readers walk their directory recursively).
type Detected struct {
	Terraform, K8s, Snapshots []string
}

// ErrUndetected is returned for a path that holds no input darb can read.
var ErrUndetected = errors.New("no Terraform files (.tf), Kubernetes manifests or darb snapshot found")

// detectHead bounds what is read of a file to recognise a manifest.
const detectHead = 64 << 10

var (
	yamlAPIVersion = regexp.MustCompile(`(?m)^apiVersion:\s*\S`)
	yamlKind       = regexp.MustCompile(`(?m)^kind:\s*\S`)
)

// DetectInputs finds, under each path (a directory relative to root), the
// directories holding .tf files, the directories holding Kubernetes
// manifests (a YAML or JSON document with apiVersion and kind), and darb
// snapshots (a manifest.json of format darb-snapshot/v1). Hidden
// directories are skipped, as the readers skip them. A path that is not a
// directory, or holds none of these, is an error naming it.
// Errors name each path as names gives it (what the user typed).
func DetectInputs(root string, paths, names []string) (*Detected, error) {
	d := &Detected{}
	for i, p := range paths {
		name := names[i]
		full := filepath.Join(root, filepath.FromSlash(p))
		fi, err := os.Stat(full)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("%s does not exist", name)
		case err != nil:
			return nil, fmt.Errorf("%s: %w", name, err)
		case !fi.IsDir():
			return nil, fmt.Errorf("%s is a file: pass a directory, or --plan FILE for a Terraform plan", name)
		}
		found, err := detectUnder(root, path.Clean(filepath.ToSlash(p)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if len(found.Terraform)+len(found.K8s)+len(found.Snapshots) == 0 {
			return nil, fmt.Errorf("%s: %w; name the input with --terraform, --k8s, --plan or --aws-snapshot", name, ErrUndetected)
		}
		d.Terraform = append(d.Terraform, found.Terraform...)
		d.K8s = append(d.K8s, found.K8s...)
		d.Snapshots = append(d.Snapshots, found.Snapshots...)
	}
	d.Terraform, d.K8s, d.Snapshots = topMost(d.Terraform), topMost(d.K8s), topMost(d.Snapshots)
	return d, nil
}

func detectUnder(root, p string) (*Detected, error) {
	d := &Detected{}
	base := filepath.Join(root, filepath.FromSlash(p))
	err := filepath.WalkDir(base, func(full string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !e.IsDir() {
			return nil
		}
		if full != base && strings.HasPrefix(e.Name(), ".") {
			return filepath.SkipDir
		}
		rel, err := filepath.Rel(root, full)
		if err != nil {
			return err
		}
		dir := path.Clean(filepath.ToSlash(rel))
		if isSnapshot(full) {
			d.Snapshots = append(d.Snapshots, dir)
			return filepath.SkipDir // its JSON files are not manifests
		}
		tf, k8s, err := kinds(full)
		if err != nil {
			return err
		}
		if tf {
			d.Terraform = append(d.Terraform, dir)
		}
		if k8s {
			d.K8s = append(d.K8s, dir)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return d, nil
}

// kinds says whether a directory itself (not its subdirectories) holds
// .tf files and Kubernetes manifests.
func kinds(dir string) (tf, k8s bool, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, false, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".tf":
			tf = true
		case ".yaml", ".yml", ".json":
			k8s = k8s || isManifest(filepath.Join(dir, e.Name()))
		}
	}
	return tf, k8s, nil
}

func head(file string) []byte {
	f, err := os.Open(file) //nolint:gosec // G304: a file under a path the user named.
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, _ := io.ReadAll(io.LimitReader(f, detectHead))
	return data
}

// isManifest: a document with apiVersion and kind at its top level.
func isManifest(file string) bool {
	data := head(file)
	if strings.EqualFold(filepath.Ext(file), ".json") {
		var top map[string]json.RawMessage
		if json.Unmarshal(bytes.TrimSpace(data), &top) != nil {
			return false
		}
		_, a := top["apiVersion"]
		_, k := top["kind"]
		return a && k
	}
	return yamlAPIVersion.Match(data) && yamlKind.Match(data)
}

func isSnapshot(dir string) bool {
	var m struct {
		Format string `json:"format"`
	}
	return json.Unmarshal(head(filepath.Join(dir, "manifest.json")), &m) == nil && m.Format == awssnapshot.Format
}

// topMost keeps the directories none of whose ancestors is kept, sorted.
func topMost(dirs []string) []string {
	slices.Sort(dirs)
	dirs = slices.Compact(dirs)
	var out []string
	for _, d := range dirs {
		covered := slices.ContainsFunc(out, func(a string) bool { return a == "." || strings.HasPrefix(d, a+"/") })
		if !covered {
			out = append(out, d)
		}
	}
	return out
}
