package terraform

import (
	"slices"
	"strconv"

	"github.com/r3oof-900/clapa/internal/collect/tfraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/model"
)

// bucketFacts accumulates what separate Terraform resources say about one bucket.
type bucketFacts struct {
	r        *tfraw.Resource
	policies []*model.PolicyDocument
	enc      model.Encryption
	restrict model.Tri
}

// data normalizes S3 buckets (+ policy, encryption, public access block),
// KMS keys (+ key policy), EKS clusters, node groups and Pod Identity.
func (n *norm) data(rs []*tfraw.Resource) {
	buckets := map[string]*bucketFacts{} // "root|bucket name" and "root|address"
	for _, r := range rs {
		if r.Type == "aws_s3_bucket" && r.Mode == "managed" {
			// Since January 2023 S3 encrypts new objects with SSE-S3 by default
			// (S3 User Guide › "Default encryption"); a config resource overrides it.
			f := &bucketFacts{r: r, enc: model.Encryption{Type: "AES256"}, restrict: model.Unknown}
			buckets[r.Root+"|"+n.nameOf(r)], buckets[r.Root+"|"+r.Address] = f, f
		}
	}
	templates := map[string]*tfraw.Resource{}
	for _, r := range rs {
		switch r.Type {
		case "aws_s3_bucket_policy", "aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_public_access_block":
			n.bucketPart(r, buckets)
		case "aws_kms_key":
			n.kmsKey(r)
		case "aws_eks_cluster":
			n.cluster(r)
		case "aws_eks_pod_identity_association":
			n.podIdentity(r)
		case "aws_launch_template":
			templates[r.Root+"|"+r.Address] = r
		}
	}
	for _, r := range rs {
		if r.Type == "aws_eks_node_group" {
			n.nodeGroup(r, templates)
		}
	}
	n.addBuckets(buckets)
}

func (n *norm) bucketPart(r *tfraw.Resource, buckets map[string]*bucketFacts) {
	f := n.bucketOf(r, buckets)
	if f == nil {
		return
	}
	switch r.Type {
	case "aws_s3_bucket_policy":
		text, ok := n.policyText(r.Root, attr(r, "policy"))
		f.policies = append(f.policies, n.parsePolicy(r, r.Address, model.PolicyResource, text, ok))
	case "aws_s3_bucket_server_side_encryption_configuration":
		for _, rule := range r.Attrs.Blocks("rule") {
			for _, d := range rule.Blocks("apply_server_side_encryption_by_default") {
				f.enc.Type, _ = n.str(r.Root, valueOf(d, "sse_algorithm"))
				if v, ok := d.Get("kms_master_key_id"); ok {
					f.enc.KeyARN, _ = n.str(r.Root, v)
				}
			}
		}
	case "aws_s3_bucket_public_access_block":
		if v, ok := r.Attrs.Get("restrict_public_buckets"); ok && v.Kind == tfraw.KBool {
			f.restrict = model.TriOf(v.Bool)
		}
	}
}

func (n *norm) bucketOf(r *tfraw.Resource, buckets map[string]*bucketFacts) *bucketFacts {
	v := attr(r, "bucket")
	if v != nil && v.Kind == tfraw.KRef {
		if f, ok := buckets[r.Root+"|"+v.Ref.Address]; ok {
			return f
		}
	}
	if name, ok := n.str(r.Root, v); ok {
		if f, ok := buckets[r.Root+"|"+name]; ok {
			return f
		}
	}
	n.gap(coverage.KindUnresolved, r, "bucket is not defined in the input; this configuration is not attached")
	return nil
}

func (n *norm) addBuckets(buckets map[string]*bucketFacts) {
	done := map[*bucketFacts]bool{}
	for _, f := range sortedFacts(buckets) {
		if done[f] {
			continue
		}
		done[f] = true
		r, s := f.r, src(f.r)
		res := model.NewResource(&model.ResourceInput{
			Kind: model.KindS3Bucket, ARN: n.arnOf(r), Account: n.account(r), Region: n.region(r), Tags: tags(r),
			Encryption: f.enc, S3: model.S3Settings{RestrictPublicBuckets: f.restrict}, Source: s,
		})
		n.b.AddResource(res)
		for _, d := range f.policies {
			n.b.AddPolicy(&model.AttachedPolicy{Target: res.ID(), Doc: d})
		}
	}
}

func sortedFacts(m map[string]*bucketFacts) []*bucketFacts {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]*bucketFacts, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

// kmsKey: a key without a policy gets the documented default key policy,
// which delegates to IAM through the account root (KMS Developer Guide ›
// "Default key policy").
func (n *norm) kmsKey(r *tfraw.Resource) {
	s := src(r)
	key := model.NewResource(&model.ResourceInput{
		Kind: model.KindKMSKey, ARN: n.arnOf(r), Account: n.account(r), Region: n.region(r), Tags: tags(r), Source: s,
	})
	n.b.AddResource(key)
	text, ok := n.policyText(r.Root, attr(r, "policy"))
	if v := attr(r, "policy"); v == nil || v.Kind == tfraw.KNull {
		text, ok = defaultKeyPolicy(n.opts.Partition, n.account(r)), true
	}
	n.b.AddPolicy(&model.AttachedPolicy{Target: key.ID(), Doc: n.parsePolicy(r, r.Address+".policy", model.PolicyResource, text, ok)})
}

func defaultKeyPolicy(partition, account string) string {
	root := "arn:" + partition + ":iam::" + account + ":root"
	if account == "" {
		root = placeholder("account") // unknown account: the delegation is UNKNOWN, not denied
	}
	return `{"Version":"2012-10-17","Id":"key-default-1","Statement":[{"Sid":"Enable IAM User Permissions","Effect":"Allow",` +
		`"Principal":{"AWS":"` + root + `"},"Action":"kms:*","Resource":"*"}]}`
}

func (n *norm) cluster(r *tfraw.Resource) {
	name := n.nameOf(r)
	issuer := n.opts.OIDCIssuers[name]
	if issuer == "" {
		n.gap(coverage.KindUnresolved, r, "OIDC issuer of cluster "+name+" is unknown: set clusters[].oidc_issuer in clapa.yaml")
	}
	n.b.AddCluster(&model.Cluster{Name: name, ARN: n.arnOf(r), Account: n.account(r), Region: n.region(r), OIDCIssuer: issuer, Source: src(r)})
}

func (n *norm) podIdentity(r *tfraw.Resource) {
	get := func(k string) string { s, _ := n.str(r.Root, attr(r, k)); return s }
	n.b.AddPodIdentity(&model.PodIdentityAssociation{
		Cluster: get("cluster_name"), Namespace: get("namespace"), ServiceAccount: get("service_account"),
		RoleARN: get("role_arn"), Source: src(r),
	})
}

// nodeGroup: IMDS settings come from the launch template; without one they
// are unknown (EKS defaults are not assumed).
func (n *norm) nodeGroup(r *tfraw.Resource, templates map[string]*tfraw.Resource) {
	get := func(k string) string { s, _ := n.str(r.Root, attr(r, k)); return s }
	ng := &model.NodeGroup{Cluster: get("cluster_name"), Name: get("node_group_name"), RoleARN: get("node_role_arn"), Source: src(r)}
	for _, lt := range r.Attrs.Blocks("launch_template") {
		if v, ok := lt.Get("id"); ok && v.Kind == tfraw.KRef {
			if t := templates[r.Root+"|"+v.Ref.Address]; t != nil {
				n.imds(t, ng)
			}
		}
	}
	if ng.HTTPTokens == "" {
		n.gap(coverage.KindUnresolved, r, "IMDS settings of node group "+ng.Name+" are unknown (no launch template metadata_options)")
	}
	n.b.AddNodeGroup(ng)
}

func (n *norm) imds(t *tfraw.Resource, ng *model.NodeGroup) {
	for _, mo := range t.Attrs.Blocks("metadata_options") {
		ng.HTTPTokens, _ = n.str(t.Root, valueOf(mo, "http_tokens"))
		ng.HTTPEndpoint, _ = n.str(t.Root, valueOf(mo, "http_endpoint"))
		if s, ok := n.str(t.Root, valueOf(mo, "http_put_response_hop_limit")); ok {
			ng.HopLimit, _ = strconv.Atoi(s)
		}
	}
}
