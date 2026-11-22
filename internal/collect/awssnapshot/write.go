package awssnapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/r3oof-900/clapa/internal/collect/awsraw"
)

// ErrWrite is returned when a bundle cannot be written.
var ErrWrite = errors.New("awssnapshot: cannot write the bundle")

// Write writes snap as a new bundle in dir (the layout Collect reads; see
// the package comment). dir must not exist: a bundle is never written over
// another directory. Every file goes through an os.Root on dir, so no name
// in the data can place a file outside it. The output is deterministic.
func Write(dir string, snap *awsraw.Snapshot) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("%w: %w (collect-snapshot writes a new directory)", ErrWrite, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrWrite, err)
	}
	defer func() { _ = root.Close() }()
	w := &writer{root: root}
	m := manifestOut{Format: Format, Accounts: []accountOut{}, Calls: []callOut{}}
	for _, a := range snap.Accounts {
		m.Accounts = append(m.Accounts, accountOut{ID: a.ID, Partition: a.Partition})
		for _, c := range a.Calls {
			m.Calls = append(m.Calls, callOut{Account: a.ID, Call: c})
		}
		w.account(a)
	}
	w.file("manifest.json", m)
	if w.err != nil {
		return fmt.Errorf("%w: %w", ErrWrite, w.err)
	}
	return nil
}

type accountOut struct {
	ID        string `json:"id"`
	Partition string `json:"partition"`
}

type callOut struct {
	Account string `json:"account"`
	awsraw.Call
}

type manifestOut struct {
	Format   string       `json:"format"`
	Accounts []accountOut `json:"accounts"`
	Calls    []callOut    `json:"calls"`
}

// writer keeps the first error; later writes are skipped.
type writer struct {
	root *os.Root
	err  error
}

var errName = errors.New("empty resource name")

// file writes v as indented JSON at rel (slash-separated components, each
// already escaped).
func (w *writer) file(rel string, v any) {
	if w.err != nil {
		return
	}
	for _, c := range strings.Split(rel, "/") {
		if c == "" {
			w.err = fmt.Errorf("%s: %w", rel, errName)
			return
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		w.err = err
		return
	}
	if d := path.Dir(rel); d != "." {
		if err := w.root.MkdirAll(d, 0o700); err != nil {
			w.err = err
			return
		}
	}
	f, err := w.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		w.err = err
		return
	}
	_, err = f.Write(buf.Bytes())
	w.err = errors.Join(err, f.Close())
}

func p(parts ...string) string {
	out := make([]string, len(parts))
	for i, s := range parts {
		out[i] = s
		if !strings.HasSuffix(s, ".json") && i > 0 {
			out[i] = escapeName(s)
		}
	}
	return strings.Join(out, "/")
}

func (w *writer) account(a *awsraw.Account) {
	if a.Auth != nil {
		w.file(path.Join(a.ID, "iam", "get-account-authorization-details.json"), a.Auth)
	}
	if a.PublicAccessBlock != nil {
		w.file(path.Join(a.ID, "s3control", "get-public-access-block.json"), map[string]any{"PublicAccessBlockConfiguration": a.PublicAccessBlock})
	}
	for _, b := range a.Buckets {
		w.bucket(a.ID, b)
	}
	aliases := map[string][]awsraw.Alias{}
	for _, al := range a.Aliases {
		aliases[al.Region] = append(aliases[al.Region], al)
	}
	for region, list := range aliases {
		w.file(p(a.ID, region, "kms", "list-aliases.json"), map[string]any{"Aliases": list})
	}
	for _, k := range a.Keys {
		w.key(a.ID, k)
	}
	for _, c := range a.Clusters {
		w.cluster(a.ID, c)
	}
	for _, s := range a.Secrets {
		w.secret(a.ID, s)
	}
	for _, prm := range a.Params {
		w.parameter(a.ID, prm)
	}
}

func (w *writer) bucket(acct string, b *awsraw.Bucket) {
	dir := func(f string) string { return p(acct, "s3", b.Name, f) }
	w.file(dir("get-bucket-location.json"), map[string]any{"LocationConstraint": b.Region})
	if b.Policy != "" {
		w.file(dir("get-bucket-policy.json"), map[string]any{"Policy": b.Policy})
	}
	if e := b.Encryption; e != nil {
		rule := map[string]any{"ApplyServerSideEncryptionByDefault": map[string]any{"SSEAlgorithm": e.SSEAlgorithm, "KMSMasterKeyID": e.KMSMasterKeyID}}
		if e.BucketKeyEnabled != nil {
			rule["BucketKeyEnabled"] = *e.BucketKeyEnabled
		}
		w.file(dir("get-bucket-encryption.json"), map[string]any{"ServerSideEncryptionConfiguration": map[string]any{"Rules": []any{rule}}})
	}
	if b.PublicAccessBlock != nil {
		w.file(dir("get-public-access-block.json"), map[string]any{"PublicAccessBlockConfiguration": b.PublicAccessBlock})
	}
	if b.Tags != nil {
		w.file(dir("get-bucket-tagging.json"), map[string]any{"TagSet": b.Tags})
	}
}

func (w *writer) key(acct string, k *awsraw.Key) {
	dir := func(f string) string { return p(acct, k.Region, "kms", k.Metadata.KeyID, f) }
	w.file(dir("describe-key.json"), map[string]any{"KeyMetadata": k.Metadata})
	if k.Policy != "" {
		w.file(dir("get-key-policy.json"), map[string]any{"PolicyName": "default", "Policy": k.Policy})
	}
	if k.RotationEnabled != nil {
		w.file(dir("get-key-rotation-status.json"), map[string]any{"KeyRotationEnabled": *k.RotationEnabled})
	}
	if k.Tags != nil {
		tags := make([]map[string]string, len(k.Tags))
		for i, t := range k.Tags {
			tags[i] = map[string]string{"TagKey": t.Key, "TagValue": t.Value}
		}
		w.file(dir("list-resource-tags.json"), map[string]any{"Tags": tags})
	}
}

func (w *writer) cluster(acct string, c *awsraw.Cluster) {
	w.file(p(acct, c.Region, "eks", c.Name, "describe-cluster.json"), map[string]any{"cluster": map[string]any{
		"name": c.Name, "arn": c.Arn, "identity": map[string]any{"oidc": map[string]any{"issuer": c.OIDCIssuer}},
	}})
	for _, a := range c.PodIdentity {
		id := a.AssociationArn[strings.LastIndex(a.AssociationArn, "/")+1:]
		w.file(p(acct, c.Region, "eks", c.Name, "pod-identity", escapeName(id)+".json"), map[string]any{"association": a})
	}
}

func (w *writer) secret(acct string, s *awsraw.Secret) {
	dir := func(f string) string { return p(acct, s.Region, "secretsmanager", s.Name, f) }
	w.file(dir("describe-secret.json"), map[string]any{"ARN": s.ARN, "Name": s.Name, "KmsKeyId": s.KMSKeyID, "Tags": s.Tags})
	if s.Policy != "" {
		w.file(dir("get-resource-policy.json"), map[string]any{"ARN": s.ARN, "Name": s.Name, "ResourcePolicy": s.Policy})
	}
}

func (w *writer) parameter(acct string, prm *awsraw.Parameter) {
	dir := func(f string) string { return p(acct, prm.Region, "ssm", prm.Name, f) }
	meta := map[string]any{"Name": prm.Name, "ARN": prm.ARN, "Type": prm.Type, "KeyId": prm.KeyID, "Tier": prm.Tier}
	w.file(dir("describe-parameters.json"), map[string]any{"Parameters": []any{meta}})
	if prm.Tags != nil {
		w.file(dir("list-tags-for-resource.json"), map[string]any{"TagList": prm.Tags})
	}
	if prm.Policies != nil {
		pols := make([]map[string]string, len(prm.Policies))
		for i, pol := range prm.Policies {
			pols[i] = map[string]string{"Policy": pol}
		}
		w.file(dir("get-resource-policies.json"), map[string]any{"Policies": pols})
	}
}
