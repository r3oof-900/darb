package terraform

import (
	"slices"
	"strconv"
	"strings"

	"github.com/r3oof-900/darb/internal/collect/tfraw"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/normalize"
)

// bucketFacts accumulates what separate Terraform resources say about one bucket.
type bucketFacts struct {
	r            *tfraw.Resource
	policies     []*model.PolicyDocument
	enc          model.Encryption
	encDefault   bool // no encryption configuration: the documented SSE-S3 default
	restrict     model.Tri
	restrictSeen bool
	// ownership: aws_s3_bucket_ownership_controls (ownershipSeen), and the
	// public grants of aws_s3_bucket_acl.
	ownership     string
	ownershipSeen bool
	publicACL     []string
}

// data normalizes S3 buckets (+ policy, encryption, public access block),
// KMS keys (+ key policy), EKS clusters, node groups and Pod Identity.
func (n *norm) data(rs []*tfraw.Resource) {
	buckets := map[string]*bucketFacts{} // "root|bucket name" and "root|address"
	for _, r := range rs {
		if r.Type == "aws_s3_bucket" && r.Mode == "managed" {
			// Since January 2023 S3 encrypts new objects with SSE-S3 by default
			// (S3 User Guide › "Default encryption"); a config resource overrides it.
			f := &bucketFacts{r: r, enc: model.Encryption{Type: "AES256", BucketKey: model.Unknown}, encDefault: true, restrict: model.Unknown}
			buckets[r.Root+"|"+n.nameOf(r)], buckets[r.Root+"|"+r.Address] = f, f
		}
	}
	templates := map[string]*tfraw.Resource{}
	single := map[string]func(*tfraw.Resource){
		"aws_kms_key": n.kmsKey, "aws_eks_cluster": n.cluster, "aws_eks_pod_identity_association": n.podIdentity,
		"aws_eks_addon": n.addon, "aws_iam_openid_connect_provider": n.oidcProvider,
		"aws_eks_access_entry": n.accessEntry, "aws_eks_access_policy_association": n.accessPolicy,
		"aws_s3_account_public_access_block": n.accountBlock, "aws_kms_grant": n.kmsGrant,
	}
	for _, r := range rs {
		switch r.Type {
		case "aws_s3_bucket_policy", "aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_public_access_block",
			"aws_s3_bucket_ownership_controls", "aws_s3_bucket_acl":
			n.bucketPart(r, buckets)
		case "aws_launch_template":
			templates[r.Root+"|"+r.Address] = r
		default:
			if f, ok := single[r.Type]; ok {
				f(r)
			}
		}
	}
	for _, r := range rs {
		if r.Type == "aws_eks_node_group" {
			n.nodeGroup(r, templates)
		}
	}
	n.addBuckets(buckets)
	n.secretsData(rs)
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
		f.encDefault = false
		f.enc.BucketKey = model.Unknown
		for _, rule := range r.Attrs.Blocks("rule") {
			if v, ok := rule.Get("bucket_key_enabled"); ok && v.Kind == tfraw.KBool {
				f.enc.BucketKey = model.TriOf(v.Bool)
			}
			for _, d := range rule.Blocks("apply_server_side_encryption_by_default") {
				f.enc.Type, _ = n.str(r.Root, valueOf(d, "sse_algorithm"))
				// Unset (or computed by the provider in a plan) means no key:
				// SSE-S3, or the AWS managed aws/s3 key for aws:kms.
				if v, ok := d.Get("kms_master_key_id"); ok && v.Kind != tfraw.KNull && !v.Computed() {
					f.enc.KeyARN, _ = n.str(r.Root, v)
				}
			}
		}
	case "aws_s3_bucket_public_access_block":
		f.restrictSeen = true
		if v, ok := r.Attrs.Get("restrict_public_buckets"); ok && v.Kind == tfraw.KBool {
			f.restrict = model.TriOf(v.Bool)
		}
	case "aws_s3_bucket_ownership_controls", "aws_s3_bucket_acl":
		n.aclPart(r, f)
	}
}

// aclPart: Object Ownership (aws_s3_bucket_ownership_controls) and the
// public grants of the bucket ACL (aws_s3_bucket_acl).
func (n *norm) aclPart(r *tfraw.Resource, f *bucketFacts) {
	if r.Type == "aws_s3_bucket_acl" {
		f.publicACL = append(f.publicACL, n.publicGrants(r)...)
		return
	}
	f.ownershipSeen = true
	for _, rule := range r.Attrs.Blocks("rule") {
		f.ownership, _ = n.str(r.Root, valueOf(rule, "object_ownership"))
	}
}

// publicGrants: the public grants of an aws_s3_bucket_acl, from its canned
// acl or its access_control_policy grants (AWS provider › aws_s3_bucket_acl).
func (n *norm) publicGrants(r *tfraw.Resource) []string {
	if acl, ok := n.str(r.Root, attr(r, "acl")); ok {
		return normalize.CannedPublicGrants(acl)
	}
	var out []string
	for _, p := range r.Attrs.Blocks("access_control_policy") {
		for _, g := range p.Blocks("grant") {
			perm, _ := n.str(r.Root, valueOf(g, "permission"))
			for _, who := range g.Blocks("grantee") {
				uri, _ := n.str(r.Root, valueOf(who, "uri"))
				if s, ok := normalize.PublicGrant(uri, perm); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
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
		var defaulted []string
		if f.encDefault {
			defaulted = append(defaulted, model.DefaultS3Encryption)
		}
		switch {
		case f.restrictSeen:
		case r.Action == "create":
			// A bucket the plan creates gets all four Block Public Access
			// settings (DESIGN.md §4.7); deterministic, since nothing outside
			// the input has changed it yet.
			f.restrict = model.True
			defaulted = append(defaulted, model.DefaultS3NewBucketBPA)
		default:
			// No deterministic default: an existing bucket's settings (or any
			// bucket's, read statically) can be changed outside this input.
			n.gap(coverage.KindUnresolved, r, "Block Public Access of this bucket is not in the input (no aws_s3_bucket_public_access_block); unknown")
		}
		s3 := model.S3Settings{RestrictPublicBuckets: f.restrict, ACLs: model.Unknown, Ownership: f.ownership, PublicACL: f.publicACL}
		switch {
		case f.ownershipSeen:
			s3.ACLs = normalize.ACLsOf(f.ownership)
			if s3.ACLs == model.Unknown {
				n.gap(coverage.KindUnresolved, r, "object_ownership of this bucket is not known statically; ACLs may be enabled")
			}
		case r.Action == "create":
			// A bucket the plan creates has ACLs disabled (DESIGN.md §4.7).
			s3.ACLs = model.False
			defaulted = append(defaulted, model.DefaultS3NewBucketACLs)
		default:
			// A bucket read statically, or one the plan does not create, may be
			// older than the April 2023 default (or imported): unknown.
			n.gap(coverage.KindUnresolved, r, normalize.OwnershipUnknown)
		}
		if d, ok := normalize.ACLGap(&s3); ok {
			n.gap(coverage.KindNotModelled, r, d)
		}
		res := model.NewResource(&model.ResourceInput{
			Kind: model.KindS3Bucket, ARN: n.arnOf(r), Account: n.account(r), Region: n.region(r), Tags: tags(r),
			Encryption: f.enc, S3: s3, Defaulted: defaulted, Source: s,
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
// accountBlock: aws_s3_account_public_access_block, the account's S3 Block
// Public Access (account_id, else the provider's account). A value that is
// not a literal is unknown.
func (n *norm) accountBlock(r *tfraw.Resource) {
	account := n.account(r)
	if v := attr(r, "account_id"); v != nil && v.Kind == tfraw.KString {
		account = v.Str
	}
	restrict := model.Unknown
	switch v := attr(r, "restrict_public_buckets"); {
	case v != nil && v.Kind == tfraw.KBool:
		restrict = model.TriOf(v.Bool)
	default:
		n.gap(coverage.KindUnresolved, r, "restrict_public_buckets of the account's Block Public Access is not known statically; unknown")
	}
	n.b.AddAccountBlock(&model.AccountPublicAccessBlock{Account: account, RestrictPublicBuckets: restrict, Source: src(r)})
}

func (n *norm) kmsKey(r *tfraw.Resource) {
	s := src(r)
	rotation, defaulted := model.Unknown, []string(nil)
	switch v := attr(r, "enable_key_rotation"); {
	case v == nil || v.Kind == tfraw.KNull || v.Computed():
		rotation, defaulted = model.False, []string{model.DefaultKeyRotationTF}
	case v.Kind == tfraw.KBool:
		rotation = model.TriOf(v.Bool)
	default:
		n.gap(coverage.KindUnresolved, r, "enable_key_rotation is not known statically")
	}
	key := model.NewResource(&model.ResourceInput{
		Kind: model.KindKMSKey, ARN: n.arnOf(r), Account: n.account(r), Region: n.region(r), Tags: tags(r),
		KeyRotation: rotation, Grants: model.GrantsTerraform, Defaulted: defaulted, Source: s,
	})
	n.b.AddResource(key)
	text, ok := n.policyText(r.Root, attr(r, "policy"))
	def := ""
	if v := attr(r, "policy"); v == nil || v.Kind == tfraw.KNull || v.Computed() {
		text, ok, def = defaultKeyPolicy(n.opts.Partition, n.account(r)), true, model.DefaultKeyPolicy
	}
	n.b.AddPolicy(&model.AttachedPolicy{Target: key.ID(), Doc: n.parsePolicy(r, r.Address+".policy", model.PolicyResource, text, ok), Default: def})
}

func defaultKeyPolicy(partition, account string) string {
	// An unknown account arrives as a placeholder, so the delegation is
	// UNKNOWN, not denied.
	root := "arn:" + partition + ":iam::" + account + ":root"
	return `{"Version":"2012-10-17","Id":"key-default-1","Statement":[{"Sid":"Enable IAM User Permissions","Effect":"Allow",` +
		`"Principal":{"AWS":"` + root + `"},"Action":"kms:*","Resource":"*"}]}`
}

func (n *norm) cluster(r *tfraw.Resource) {
	name := n.nameOf(r)
	c := &model.Cluster{Name: name, ARN: n.arnOf(r), Account: n.account(r), Region: n.region(r), Source: src(r)}
	c.OIDCIssuer = n.opts.OIDCIssuers[c.Key()]
	if c.OIDCIssuer == "" {
		n.gap(coverage.KindUnresolved, r, "OIDC issuer of cluster "+name+" is unknown: set clusters[].oidc_issuer in darb.yaml")
	}
	n.b.AddCluster(c)
}

// podIdentity: aws_eks_pod_identity_association (cluster_name, namespace,
// service_account, role_arn, target_role_arn, disable_session_tags).
func (n *norm) podIdentity(r *tfraw.Resource) {
	get := func(k string) string {
		if v := attr(r, k); v == nil || v.Kind == tfraw.KNull || v.Computed() {
			return ""
		}
		s, _ := n.str(r.Root, attr(r, k))
		return s
	}
	disabled, defaulted := model.Unknown, []string(nil)
	switch v := attr(r, "disable_session_tags"); {
	case v == nil || v.Kind == tfraw.KNull || v.Computed():
		disabled, defaulted = model.False, []string{model.DefaultPodIdentitySTags}
	case v.Kind == tfraw.KBool:
		disabled = model.TriOf(v.Bool)
	default:
		n.gap(coverage.KindUnresolved, r, "disable_session_tags is not known; whether sts:TagSession is needed is unknown")
	}
	n.b.AddPodIdentity(&model.PodIdentityAssociation{
		Cluster: n.clusterKey(r, get("cluster_name")), Namespace: get("namespace"), ServiceAccount: get("service_account"),
		RoleARN: get("role_arn"), TargetRoleARN: get("target_role_arn"), SessionTagsDisabled: disabled, Defaulted: defaulted, Source: src(r),
	})
}

func (n *norm) addon(r *tfraw.Resource) {
	cluster, _ := n.str(r.Root, attr(r, "cluster_name"))
	name, _ := n.str(r.Root, attr(r, "addon_name"))
	n.b.AddAddon(&model.ClusterAddon{Cluster: n.clusterKey(r, cluster), Name: name, Source: src(r)})
}

// nodeGroup: IMDS settings come from the launch template; without one they
// are unknown (EKS defaults are not assumed).
func (n *norm) nodeGroup(r *tfraw.Resource, templates map[string]*tfraw.Resource) {
	get := func(k string) string { s, _ := n.str(r.Root, attr(r, k)); return s }
	ng := &model.NodeGroup{Cluster: n.clusterKey(r, get("cluster_name")), Name: get("node_group_name"), RoleARN: get("node_role_arn"), Source: src(r)}
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

// oidcProvider: aws_iam_openid_connect_provider (url, client_id_list). An
// unresolved client ID stays a placeholder, so matching it is UNKNOWN.
func (n *norm) oidcProvider(r *tfraw.Resource) {
	url, _ := n.str(r.Root, attr(r, "url"))
	host := strings.TrimPrefix(url, "https://")
	p := &model.OIDCProvider{
		ARN: "arn:" + n.opts.Partition + ":iam::" + n.account(r) + ":oidc-provider/" + host, Account: n.account(r), Source: src(r),
	}
	if v := attr(r, "client_id_list"); v != nil {
		for _, item := range listItems(v) {
			s, _ := n.str(r.Root, item)
			p.ClientIDs = append(p.ClientIDs, s)
		}
	}
	n.b.AddOIDCProvider(p)
}
