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
	if line, found := collect.FindReservedJSON(data); found {
		return &collect.ReservedTextError{Line: line} // the file is rejected
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
	if g := c.Gap(Name, account); g != nil {
		r.rec.Add(g)
	}
}

// account reads every file under <account>/ by its place in the layout.
func (r *reader) account(a *awsraw.Account, files []string) {
	l := &layout{
		buckets: map[string]*awsraw.Bucket{}, keys: map[string]*awsraw.Key{}, clusters: map[string]*awsraw.Cluster{},
		secrets: map[string]*awsraw.Secret{}, params: map[string]*awsraw.Parameter{},
	}
	for _, f := range files {
		parts := strings.Split(f, "/")
		if parts[0] != a.ID {
			continue
		}
		if err := r.place(a, l, f, parts); err != nil {
			line := 0
			if re := (*collect.ReservedTextError)(nil); errors.As(err, &re) {
				line = re.Line
			}
			r.gap(&coverage.Gap{Kind: kindFor(err), Account: a.ID, File: path.Join(r.in.Path, f), Line: line, Detail: err.Error()})
		}
	}
	a.Buckets, a.Keys, a.Clusters = sortedValues(l.buckets), sortedValues(l.keys), sortedValues(l.clusters)
	a.Secrets, a.Params, a.Aliases = sortedValues(l.secrets), sortedValues(l.params), l.aliases
	failedPolicies(a)
}

// layout collects one account's resources by their directory.
type layout struct {
	buckets  map[string]*awsraw.Bucket
	keys     map[string]*awsraw.Key
	clusters map[string]*awsraw.Cluster
	secrets  map[string]*awsraw.Secret
	params   map[string]*awsraw.Parameter
	aliases  []awsraw.Alias
}

func (r *reader) place(a *awsraw.Account, l *layout, f string, parts []string) error {
	if f == path.Join(a.ID, "iam", "get-account-authorization-details.json") {
		a.Auth = &awsraw.AuthorizationDetails{}
		return r.json(f, a.Auth)
	}
	if len(parts) < 4 {
		return errUnknownFile
	}
	if parts[1] == "s3" && len(parts) == 4 {
		name, err := unescapeName(parts[2])
		if err != nil {
			return err
		}
		return r.bucketFile(bucket(l.buckets, name), f, parts[3])
	}
	return r.placeRegional(l, f, parts)
}

// placeRegional places <account>/<region>/<service>/... files.
func (r *reader) placeRegional(l *layout, f string, parts []string) error {
	region, service := parts[1], parts[2]
	if service == "kms" && len(parts) == 4 && parts[3] == "list-aliases.json" {
		return r.aliasFile(l, region, f)
	}
	if len(parts) < 5 {
		return errUnknownFile
	}
	name, err := unescapeName(parts[3])
	if err != nil {
		return err
	}
	switch {
	case service == "kms" && len(parts) == 5:
		return r.keyFile(key(l.keys, region, name), f, parts[4])
	case service == "eks":
		return r.clusterFile(cluster(l.clusters, region, name), f, parts[4:])
	case service == "secretsmanager" && len(parts) == 5:
		return r.secretFile(entry(l.secrets, region+"/"+name, func() *awsraw.Secret { return &awsraw.Secret{Region: region, Name: name} }), f, parts[4])
	case service == "ssm" && len(parts) == 5:
		return r.parameterFile(entry(l.params, region+"/"+name, func() *awsraw.Parameter { return &awsraw.Parameter{Region: region, Name: name} }), f, parts[4])
	}
	return errUnknownFile
}

func entry[V any](m map[string]*V, k string, mk func() *V) *V {
	if m[k] == nil {
		m[k] = mk()
	}
	return m[k]
}

// failedPolicies: a resource policy whose call the manifest records as
// failed is unknown, not absent (no file is written for it).
func failedPolicies(a *awsraw.Account) {
	failed := map[string]bool{}
	for _, c := range a.Calls {
		if c.Status != awsraw.StatusOK {
			failed[c.Service+" "+c.API+" "+c.Target] = true
		}
	}
	for _, b := range a.Buckets {
		b.PolicyFailed = failed["s3 GetBucketPolicy "+b.Name]
	}
	for _, s := range a.Secrets {
		s.PolicyFailed = failed["secretsmanager GetResourcePolicy "+s.ARN]
	}
	for _, prm := range a.Params {
		prm.PolicyFailed = failed["ssm GetResourcePolicies "+prm.ARN]
	}
}

var errUnknownFile = errors.New("file is not part of the " + Format + " layout (ignored)")

func kindFor(err error) coverage.Kind {
	if errors.Is(err, errUnknownFile) || errors.Is(err, errEscape) {
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
