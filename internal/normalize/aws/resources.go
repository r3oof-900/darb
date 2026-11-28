package aws

import (
	"encoding/json"
	"strings"

	"github.com/r3oof-900/darb/internal/collect/awsraw"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/managedpolicies"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/normalize"
)

const apiAuthDetails = "iam:GetAccountAuthorizationDetails"

// iam: roles with trust, inline, attached managed policies and boundaries;
// users, groups and credentials (users.go).
func (n *norm) iam() {
	if n.acct.Auth == nil {
		n.gap(coverage.KindNotModelled, "", "the snapshot has no IAM authorization details; IAM is not covered for this account")
		return
	}
	for i := range n.acct.Auth.Policies {
		p := &n.acct.Auth.Policies[i]
		n.managed[p.Arn] = p
	}
	for i := range n.acct.Auth.RoleDetailList {
		n.role(&n.acct.Auth.RoleDetailList[i])
	}
	n.users()
}

func (n *norm) role(r *awsraw.RoleDetail) {
	loc := apiLoc(r.Arn, apiAuthDetails)
	p := model.NewPrincipal(model.KindIAMRole, r.Arn, n.acct.ID, &loc)
	n.b.AddPrincipal(p)
	n.b.AddTrust(model.NewTrustRelationship(p.ID(), n.parse(r.AssumeRolePolicyDocument, r.Arn+"#trust", model.PolicyResource, &loc)))
	for _, ip := range r.RolePolicyList {
		n.b.AddPolicy(&model.AttachedPolicy{Target: p.ID(), Doc: n.parse(ip.PolicyDocument, r.Arn+"#inline/"+ip.PolicyName, model.PolicyIdentity, &loc)})
	}
	for _, ap := range r.AttachedManagedPolicies {
		n.b.AddPolicy(&model.AttachedPolicy{Target: p.ID(), Doc: n.managedDoc(ap.PolicyArn, model.PolicyIdentity)})
	}
	if r.PermissionsBoundary != nil && r.PermissionsBoundary.PermissionsBoundaryArn != "" {
		n.b.AddBoundary(&model.AttachedPolicy{Target: p.ID(), Doc: n.managedDoc(r.PermissionsBoundary.PermissionsBoundaryArn, model.PolicyBoundary)})
	}
}

// managedDoc resolves a managed policy: customer managed from the
// authorization details (default version), AWS managed from the vendored
// snapshot, else unknown and a coverage gap.
func (n *norm) managedDoc(policyARN string, kind model.PolicyKind) *model.PolicyDocument {
	loc := apiLoc(policyARN, apiAuthDetails)
	if p, ok := n.managed[policyARN]; ok {
		for _, v := range p.PolicyVersionList {
			if v.IsDefaultVersion || v.VersionID == p.DefaultVersionID {
				return n.parse(v.Document, policyARN, kind, &loc)
			}
		}
	}
	if managedpolicies.IsAWSManaged(policyARN) {
		if p, ok := n.mp.Lookup(policyARN); ok {
			return n.parse(p.Document, policyARN, kind, &loc)
		}
	}
	n.gap(coverage.KindNotModelled, policyARN, "managed policy document not available; treated as unknown")
	return n.unknownDoc(policyARN, kind, &loc)
}

func (n *norm) keys() {
	for _, k := range n.acct.Keys {
		loc := apiLoc(k.Metadata.Arn, "kms:GetKeyPolicy")
		rotation, defaulted := optionalTri(k.RotationEnabled), []string(nil)
		switch {
		case k.RotationEnabled == nil && k.Metadata.KeyManager == "AWS":
			rotation, defaulted = model.True, []string{model.DefaultAWSManagedKeyRot}
		case k.RotationEnabled == nil:
			n.gap(coverage.KindUnresolved, k.Metadata.Arn, "key rotation status was not collected (kms:GetKeyRotationStatus); unknown")
		}
		grants := model.GrantsNotCollected
		if k.Grants != nil {
			grants = model.GrantsListed
		}
		key := model.NewResource(&model.ResourceInput{
			Kind: model.KindKMSKey, ARN: k.Metadata.Arn, Account: n.acct.ID, Region: k.Region, Tags: tagMap(k.Tags),
			KeyRotation: rotation, Grants: grants, Defaulted: defaulted, Source: loc,
		})
		n.b.AddResource(key)
		raw, _ := json.Marshal(k.Policy)
		n.b.AddPolicy(&model.AttachedPolicy{Target: key.ID(), Doc: n.parse(raw, k.Metadata.Arn+"#key-policy", model.PolicyResource, &loc)})
		n.grants(key, k)
	}
}

// grants: each listed grant is a resource policy of its key
// (normalize.GrantPolicy). A grant whose grantee is a service principal
// (an AWS service using the key on the account's behalf) is kept too: it
// never starts a path from a workload.
func (n *norm) grants(key *model.Resource, k *awsraw.Key) {
	gloc := apiLoc(k.Metadata.Arn, "kms:ListGrants")
	for _, g := range k.Grants {
		grant := &normalize.Grant{ID: g.GrantID, Grantee: g.GranteePrincipal, Operations: g.Operations}
		if c := g.Constraints; c != nil {
			grant.Equals, grant.Subset = c.EncryptionContextEquals, c.EncryptionContextSubset
		}
		raw, _ := json.Marshal(normalize.GrantPolicy(grant))
		n.b.AddPolicy(&model.AttachedPolicy{Target: key.ID(), Doc: n.parse(raw, normalize.GrantDocID(k.Metadata.Arn, g.GrantID), model.PolicyResource, &gloc)})
	}
}

// accountBlock: the account's S3 Block Public Access, when collected; a
// failed call is unknown, never "off".
func (n *norm) accountBlock() {
	a := n.acct
	loc := apiLoc(a.ID, "s3:GetAccountPublicAccessBlock") // the account, not an ARN: S3 Block Public Access has none
	switch {
	case a.PublicAccessBlockFailed:
		n.b.AddAccountBlock(&model.AccountPublicAccessBlock{Account: a.ID, RestrictPublicBuckets: model.Unknown, Source: loc})
	case a.PublicAccessBlock != nil:
		n.b.AddAccountBlock(&model.AccountPublicAccessBlock{Account: a.ID, RestrictPublicBuckets: model.TriOf(a.PublicAccessBlock.RestrictPublicBuckets), Source: loc})
	}
}

func (n *norm) buckets() {
	for _, b := range n.acct.Buckets {
		arn := "arn:" + n.acct.Partition + ":s3:::" + b.Name
		loc := apiLoc(arn, "s3:GetBucketPolicy")
		enc := model.Encryption{BucketKey: model.Unknown} // unknown unless get-bucket-encryption was collected
		if b.Encryption != nil {
			enc = model.Encryption{Type: b.Encryption.SSEAlgorithm, BucketKey: optionalTri(b.Encryption.BucketKeyEnabled)}
			if strings.HasPrefix(enc.Type, "aws:kms") {
				enc.KeyARN = n.keyARN(b.Region, b.Encryption.KMSMasterKeyID, "alias/aws/s3")
			}
		}
		restrict := model.Unknown
		if b.PublicAccessBlock != nil {
			restrict = model.TriOf(b.PublicAccessBlock.RestrictPublicBuckets)
		}
		s3 := n.ownership(b, arn)
		s3.RestrictPublicBuckets = restrict
		res := model.NewResource(&model.ResourceInput{
			Kind: model.KindS3Bucket, ARN: arn, Account: n.acct.ID, Region: b.Region, Tags: tagMap(b.Tags),
			Encryption: enc, S3: s3, Source: loc,
		})
		n.b.AddResource(res)
		switch {
		case b.PolicyFailed:
			// The policy could not be read: unknown, never "no policy".
			n.b.AddPolicy(&model.AttachedPolicy{Target: res.ID(), Doc: n.unknownDoc(arn+"#bucket-policy", model.PolicyResource, &loc)})
		case b.Policy != "":
			raw, _ := json.Marshal(b.Policy)
			n.b.AddPolicy(&model.AttachedPolicy{Target: res.ID(), Doc: n.parse(raw, arn+"#bucket-policy", model.PolicyResource, &loc)})
		}
	}
}

func (n *norm) clusters() {
	for _, c := range n.acct.Clusters {
		cluster := &model.Cluster{Name: c.Name, ARN: c.Arn, Account: n.acct.ID, Region: c.Region, OIDCIssuer: c.OIDCIssuer, Source: apiLoc(c.Arn, "eks:DescribeCluster")}
		if cluster.ARN == "" {
			cluster.ARN = model.EKSClusterARN(n.acct.Partition, c.Region, n.acct.ID, c.Name)
		}
		// The same cluster may come from another input (Terraform, another
		// snapshot): one node; clusters of one name in two regions or
		// accounts have two ARNs, so two nodes.
		if !n.b.Has(model.NewID("cluster", cluster.Key())) {
			n.b.AddCluster(cluster)
		}
		for _, a := range c.PodIdentity {
			n.b.AddPodIdentity(&model.PodIdentityAssociation{
				Cluster: cluster.Key(), Namespace: a.Namespace, ServiceAccount: a.ServiceAccount, RoleARN: a.RoleArn,
				TargetRoleARN: a.TargetRoleArn, SessionTagsDisabled: optionalTri(a.DisableSessionTags),
				Source: apiLoc(a.AssociationArn, "eks:DescribePodIdentityAssociation"),
			})
		}
	}
}

// optionalTri: a boolean the snapshot may not record is unknown, not false.
func optionalTri(b *bool) model.Tri {
	if b == nil {
		return model.Unknown
	}
	return model.TriOf(*b)
}

// ownership: Object Ownership and the public grants of the bucket ACL. Not
// collected (a snapshot that predates it): unknown, named in the S3 ACLs
// note; a failed call is a gap of its own. A bucket with no ownership
// controls predates the setting: ACLs enabled. With ACLs enabled, the
// object ACLs are not collected: a gap.
func (n *norm) ownership(b *awsraw.Bucket, arn string) model.S3Settings {
	s := model.S3Settings{ACLs: model.Unknown}
	if b.Ownership == nil {
		return s
	}
	s.Ownership, s.ACLs = *b.Ownership, normalize.ACLsOf(*b.Ownership)
	if *b.Ownership == "" {
		s.ACLs = model.True
	}
	for _, g := range b.ACL {
		if p, ok := normalize.PublicGrant(g.Grantee.URI, g.Permission); ok {
			s.PublicACL = append(s.PublicACL, p)
		}
	}
	if d, ok := normalize.ACLGap(&s); ok {
		n.gap(coverage.KindNotModelled, arn, d)
	}
	return s
}
