package terraform

import (
	"fmt"
	"strings"

	"github.com/r3oof-900/darb/internal/collect/tfraw"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/managedpolicies"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/normalize"
)

// Name identifies this normalizer in coverage gaps.
const Name = "normalize-terraform"

// Options supply what Terraform inputs often do not state.
type Options struct {
	Account   string // default account when the provider does not pin one
	Region    string // default region when the provider does not set one
	Partition string // "aws" unless stated
	// OIDCIssuers maps cluster keys (model.ClusterKey) to IRSA issuer URLs
	// (from darb.yaml).
	OIDCIssuers map[string]string
}

// Normalize converts Terraform resources into canonical nodes and relations.
func Normalize(m *tfraw.Module, opts *Options, mp *managedpolicies.Snapshot, b *normalize.Builder, rec *coverage.Recorder) {
	n := &norm{
		opts: opts, mp: mp, b: b, rec: rec,
		byAddr: map[string]*tfraw.Resource{}, providers: map[string]*tfraw.Provider{}, incomplete: map[string]string{},
	}
	if n.opts.Partition == "" {
		n.opts.Partition = "aws"
	}
	for _, p := range m.Providers {
		n.providers[p.Key] = p
	}
	for _, r := range m.Resources {
		n.byAddr[r.Root+"|"+r.Address] = r
	}
	n.rejectReserved(m)
	n.iam(m.Resources)
	n.data(m.Resources)
}

type norm struct {
	opts      *Options
	mp        *managedpolicies.Snapshot
	b         *normalize.Builder
	rec       *coverage.Recorder
	byAddr    map[string]*tfraw.Resource // "root|address"
	providers map[string]*tfraw.Provider // "root:aws", "root:aws.alias"
	// incomplete maps rendered policy documents with unmodelled merged inputs to their address.
	incomplete map[string]string
}

func (n *norm) gap(kind coverage.Kind, r *tfraw.Resource, detail string) {
	n.rec.Add(&coverage.Gap{Kind: kind, Source: Name, File: r.Pos.File, Line: r.Pos.StartLine, Address: r.Address, Detail: detail})
}

// lookup finds a referenced resource in the same root; static count/for_each
// resources are stored with a "[*]" suffix.
func (n *norm) lookup(root, address string) *tfraw.Resource {
	if r, ok := n.byAddr[root+"|"+address]; ok {
		return r
	}
	return n.byAddr[root+"|"+address+"[*]"]
}

func src(r *tfraw.Resource) model.SourceLocation {
	return model.FileLocation(r.Pos.File, r.Pos.StartLine, r.Pos.EndLine, r.Address)
}

// provider returns the AWS provider configuration of a resource.
func (n *norm) provider(r *tfraw.Resource) *tfraw.Provider {
	key := r.Provider
	if key == "" || strings.Contains(key, "/") { // plan: "registry.terraform.io/hashicorp/aws"
		key = "aws"
	}
	if p, ok := n.providers[r.Root+":"+key]; ok {
		return p
	}
	return n.providers[r.Root+":aws"]
}

// account and region: provider first, then options. When neither knows the
// value it is an unresolved placeholder (one per Terraform root), never "":
// an empty ARN segment is a literal that would make policies with a literal
// account definitely not match, hiding a real path (docs/DESIGN.md 4.6).
func (n *norm) account(r *tfraw.Resource) string {
	if p := n.provider(r); p != nil && p.Account != nil && p.Account.Kind == tfraw.KString {
		return p.Account.Str
	}
	if n.opts.Account != "" {
		return n.opts.Account
	}
	n.gap(coverage.KindUnresolved, r, "account unknown: set terraform.account in darb.yaml or allowed_account_ids on the provider")
	return n.placeholder("account_of_" + r.Root)
}

func (n *norm) region(r *tfraw.Resource) string {
	if p := n.provider(r); p != nil && p.Region != nil && p.Region.Kind == tfraw.KString {
		return p.Region.Str
	}
	if n.opts.Region != "" {
		return n.opts.Region
	}
	n.gap(coverage.KindUnresolved, r, "region unknown: set terraform.region in darb.yaml or region on the provider")
	return n.placeholder("region_of_" + r.Root)
}

// pendingID is the deterministic stand-in for a value AWS generates at apply
// time and no policy can name literally: a KMS key ID, or the name of a
// bucket/role created without a name: "tf-<address>".
func pendingID(r *tfraw.Resource) string { return "tf-" + r.Address }

// clusterKey is the key of the cluster a resource names by cluster_name,
// in the resource's account and region: the cluster's ARN when both are
// known, otherwise the name (model.ClusterKey).
func (n *norm) clusterKey(r *tfraw.Resource, name string) string {
	return model.ClusterKey(model.EKSClusterARN(n.opts.Partition, n.region(r), n.account(r), name), name)
}

// arnOf returns the resource's ARN: the real one when Terraform knows it,
// otherwise a deterministic synthetic ARN of the same shape.
func (n *norm) arnOf(r *tfraw.Resource) string {
	if a, ok := r.Attrs.Str("arn"); ok && a != "" {
		return a
	}
	p := n.opts.Partition
	switch r.Type {
	case "aws_iam_role", "aws_iam_policy", "aws_iam_user":
		kind := strings.TrimPrefix(r.Type, "aws_iam_")
		return fmt.Sprintf("arn:%s:iam::%s:%s%s%s", p, n.account(r), kind, n.pathOf(r), n.nameOf(r))
	case "aws_kms_key":
		return fmt.Sprintf("arn:%s:kms:%s:%s:key/%s", p, n.region(r), n.account(r), pendingID(r))
	case "aws_s3_bucket":
		return fmt.Sprintf("arn:%s:s3:::%s", p, n.nameOf(r))
	case "aws_eks_cluster":
		return fmt.Sprintf("arn:%s:eks:%s:%s:cluster/%s", p, n.region(r), n.account(r), n.nameOf(r))
	case "aws_secretsmanager_secret":
		return fmt.Sprintf("arn:%s:secretsmanager:%s:%s:secret:%s-tfpend", p, n.region(r), n.account(r), n.nameOf(r))
	case "aws_ssm_parameter":
		return fmt.Sprintf("arn:%s:ssm:%s:%s:parameter/%s", p, n.region(r), n.account(r), strings.TrimPrefix(n.nameOf(r), "/"))
	case "aws_iam_openid_connect_provider":
		url, _ := n.str(r.Root, attr(r, "url"))
		return fmt.Sprintf("arn:%s:iam::%s:oidc-provider/%s", p, n.account(r), strings.TrimPrefix(url, "https://"))
	}
	return "arn:darb:terraform:::" + r.Root + "/" + r.Address
}

// nameOf returns the resource's name attribute ("bucket" for S3). A name
// that is set but not resolvable keeps its unresolved placeholders
// ("${var.env}-pii" → "<placeholder>-pii"): a policy naming the real bucket
// may match it, so the decision must be UNKNOWN, not a definite no. A
// name_prefix/bucket_prefix becomes the prefix plus an unresolved suffix.
// Only a name AWS generates entirely (none set) is a pending ID.
func (n *norm) nameOf(r *tfraw.Resource) string {
	key := "name"
	if r.Type == "aws_s3_bucket" {
		key = "bucket"
	}
	if v, ok := r.Attrs.Get(key); ok && v.Kind != tfraw.KNull {
		s, _ := n.str(r.Root, v)
		return s
	}
	if v, ok := r.Attrs.Get(key + "_prefix"); ok && v.Kind != tfraw.KNull {
		prefix, _ := n.str(r.Root, v)
		return prefix + n.placeholder(r.Address+".generated_suffix")
	}
	return pendingID(r)
}

func (n *norm) pathOf(r *tfraw.Resource) string {
	if s, ok := r.Attrs.Str("path"); ok && s != "" {
		return s
	}
	return "/"
}

func attr(r *tfraw.Resource, key string) *tfraw.Value {
	v, _ := r.Attrs.Get(key)
	return v
}

func tags(r *tfraw.Resource) map[string]string {
	out := map[string]string{}
	v, ok := r.Attrs.Get("tags")
	if !ok || v.Kind != tfraw.KObject {
		return out
	}
	for _, k := range v.Obj.Keys() {
		if s, ok := v.Obj.Str(k); ok {
			out[k] = s
		}
	}
	return out
}
