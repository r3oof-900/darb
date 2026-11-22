package app

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"slices"

	"github.com/r3oof-900/darb/internal/collect/awsraw"
	"github.com/r3oof-900/darb/pkg/schema"
)

// Scanned input kinds (the report's inputs, DESIGN.md §11).
const (
	inputTerraformDir  = "terraform-dir"
	inputTerraformPlan = "terraform-plan"
	inputK8sManifests  = "k8s-manifests"
	inputAWSSnapshot   = "aws-snapshot"
	inputAWSLive       = "aws-live"
	inputK8sLive       = "k8s-live"
)

// recordFiles adds a path input of the scan root and the digest of its files.
func (l *loader) recordFiles(kind, p, cluster string, accounts []string) {
	l.inputs = append(l.inputs, schema.ScannedInput{
		Kind: kind, Path: path.Clean(p), Cluster: cluster, Accounts: accounts, Digest: digestFiles(l.in.Root, p),
	})
}

// recordLive adds a live input and the digest of what was collected.
func (l *loader) recordLive(kind, cluster string, accounts, regions []string, collected any) {
	l.inputs = append(l.inputs, schema.ScannedInput{
		Kind: kind, Cluster: cluster, Accounts: accounts, Regions: regions, Digest: digestJSON(collected),
	})
}

func accountsOf(s *awsraw.Snapshot) []string {
	var out []string
	for _, a := range s.Accounts {
		if !slices.Contains(out, a.ID) {
			out = append(out, a.ID)
		}
	}
	slices.Sort(out)
	return out
}

// digestFiles: the SHA-256 of the regular files at p under root (a file, or
// every file below a directory in lexical order), each as its slash path
// relative to p, its length and its content; symbolic links are not
// followed (the collectors do not follow them either). An unreadable input
// has the digest of nothing: its collector reports the error.
func digestFiles(root, p string) string {
	h := sha256.New()
	fsys := os.DirFS(root)
	start := path.Clean(p)
	_ = fs.WalkDir(fsys, start, func(name string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil //nolint:nilerr // unreadable entries are the collector's to report
		}
		data, rerr := fs.ReadFile(fsys, name)
		if rerr != nil {
			return nil //nolint:nilerr // as above
		}
		rel := name[len(start):]
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(data)))
		h.Write([]byte(rel + "\x00"))
		h.Write(n[:])
		h.Write(data)
		return nil
	})
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// digestJSON: the SHA-256 of v as JSON (map keys sorted, so stable).
func digestJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		b = nil
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
