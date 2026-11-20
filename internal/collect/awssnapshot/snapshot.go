package awssnapshot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/awsraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/safeio"
)

// Name identifies this collector in coverage gaps.
const Name = "aws-snapshot"

// Format is the snapshot format this reader understands.
const Format = "clapa-snapshot/v1"

// ErrFormat is returned when manifest.json is missing or of another format.
var ErrFormat = errors.New("awssnapshot: not a " + Format + " bundle")

// Bundle layout (written by "clapa collect-snapshot", docs/DESIGN.md 4.3):
//
//	manifest.json
//	<account>/iam/get-account-authorization-details.json
//	<account>/s3/<bucket>/{get-bucket-policy,get-bucket-encryption,get-public-access-block,get-bucket-tagging,get-bucket-location}.json
//	<account>/<region>/kms/<key-id>/{describe-key,get-key-policy,get-key-rotation-status}.json
//	<account>/<region>/eks/<cluster>/describe-cluster.json
//	<account>/<region>/eks/<cluster>/pod-identity/<association-id>.json
type manifest struct {
	Format   string `json:"format"`
	Accounts []struct {
		ID        string `json:"id"`
		Partition string `json:"partition"`
	} `json:"accounts"`
	Calls []struct {
		Account string `json:"account"`
		awsraw.Call
	} `json:"calls"`
}

// Collect reads a snapshot bundle. Every call the manifest records as failed
// (access denied, throttled, ...) is a coverage gap; files CLAPA does not
// recognise are reported, not ignored.
func Collect(ctx context.Context, in *collect.Input, rec *coverage.Recorder) (*awsraw.Snapshot, error) {
	r := &reader{base: filepath.Join(in.Root, filepath.FromSlash(in.Path)), in: in, rec: rec}
	var m manifest
	if err := r.json("manifest.json", &m); err != nil {
		return nil, fmt.Errorf("%w (%s/manifest.json): %w", ErrFormat, in.Path, err)
	}
	if m.Format != Format {
		return nil, fmt.Errorf("%w (%s/manifest.json has format %q)", ErrFormat, in.Path, m.Format)
	}
	files, err := safeio.Walk(r.base, []string{".json"})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	snap := &awsraw.Snapshot{}
	for _, a := range m.Accounts {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		acct := &awsraw.Account{ID: a.ID, Partition: a.Partition}
		for _, c := range m.Calls {
			if c.Account == a.ID {
				acct.Calls = append(acct.Calls, c.Call)
				r.callGap(a.ID, &c.Call)
			}
		}
		r.account(acct, files)
		snap.Accounts = append(snap.Accounts, acct)
	}
	return snap, nil
}

type reader struct {
	base string
	in   *collect.Input
	rec  *coverage.Recorder
}

func (r *reader) json(rel string, v any) error {
	data, err := safeio.ReadFile(r.base, rel, r.in.Limits)
	if err != nil {
		return err
	}
	if err := safeio.CheckJSONDepth(data, r.in.Limits.MaxDepth); err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", rel, err)
	}
	return nil
}

func (r *reader) gap(g *coverage.Gap) {
	g.Source = Name
	r.rec.Add(g)
}

func (r *reader) callGap(account string, c *awsraw.Call) {
	kind := map[string]coverage.Kind{
		"AccessDenied": coverage.KindAccessDenied, "Throttling": coverage.KindThrottled, "Timeout": coverage.KindTimeout,
	}[c.Status]
	switch {
	case c.Status == "ok":
		return
	case kind == "":
		kind = coverage.KindAPIError
	}
	r.gap(&coverage.Gap{Kind: kind, Account: account, Service: c.Service, Region: c.Region, API: c.API, Address: c.Target, Detail: c.Error})
}

// account reads every file under <account>/ by its place in the layout.
func (r *reader) account(a *awsraw.Account, files []string) {
	buckets := map[string]*awsraw.Bucket{}
	keys := map[string]*awsraw.Key{}
	clusters := map[string]*awsraw.Cluster{}
	for _, f := range files {
		parts := strings.Split(f, "/")
		if parts[0] != a.ID {
			continue
		}
		var err error
		switch {
		case f == path.Join(a.ID, "iam", "get-account-authorization-details.json"):
			a.Auth = &awsraw.AuthorizationDetails{}
			err = r.json(f, a.Auth)
		case len(parts) == 4 && parts[1] == "s3":
			err = r.bucketFile(bucket(buckets, parts[2]), f, parts[3])
		case len(parts) == 5 && parts[2] == "kms":
			err = r.keyFile(key(keys, parts[1], parts[3]), f, parts[4])
		case len(parts) >= 5 && parts[2] == "eks":
			err = r.clusterFile(cluster(clusters, parts[1], parts[3]), f, parts[4:])
		default:
			err = errUnknownFile
		}
		if err != nil {
			r.gap(&coverage.Gap{Kind: kindFor(err), Account: a.ID, File: path.Join(r.in.Path, f), Detail: err.Error()})
		}
	}
	a.Buckets, a.Keys, a.Clusters = sortedValues(buckets), sortedValues(keys), sortedValues(clusters)
}

var errUnknownFile = errors.New("file is not part of the " + Format + " layout (ignored)")

func kindFor(err error) coverage.Kind {
	if errors.Is(err, errUnknownFile) {
		return coverage.KindUnsupported
	}
	return coverage.KindParseError
}

func bucket(m map[string]*awsraw.Bucket, name string) *awsraw.Bucket {
	if m[name] == nil {
		m[name] = &awsraw.Bucket{Name: name}
	}
	return m[name]
}

func key(m map[string]*awsraw.Key, region, id string) *awsraw.Key {
	k := region + "/" + id
	if m[k] == nil {
		m[k] = &awsraw.Key{Region: region, Metadata: awsraw.KeyMetadata{KeyID: id}}
	}
	return m[k]
}

func cluster(m map[string]*awsraw.Cluster, region, name string) *awsraw.Cluster {
	k := region + "/" + name
	if m[k] == nil {
		m[k] = &awsraw.Cluster{Region: region, Name: name}
	}
	return m[k]
}

func sortedValues[V any](m map[string]*V) []*V {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]*V, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}
