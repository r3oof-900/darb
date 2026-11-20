package aws

import (
	"encoding/json"

	"github.com/r3oof-900/clapa/internal/collect/awsraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/managedpolicies"
	"github.com/r3oof-900/clapa/internal/model"
)

const apiAuthDetails = "iam:GetAccountAuthorizationDetails"

// iam: roles with trust, inline, attached managed policies and boundaries.
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
	if len(n.acct.Auth.UserDetailList) > 0 || len(n.acct.Auth.GroupDetailList) > 0 {
		n.gap(coverage.KindNotModelled, "", "IAM users and groups are not yet analysed as entry points (MVP: roles)")
	}
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
		if k.RotationEnabled == nil {
			n.gap(coverage.KindUnresolved, k.Metadata.Arn, "key rotation status was not collected (kms:GetKeyRotationStatus); unknown")
		}
		key := model.NewResource(&model.ResourceInput{
			Kind: model.KindKMSKey, ARN: k.Metadata.Arn, Account: n.acct.ID, Region: k.Region, Tags: tagMap(k.Tags),
			KeyRotation: optionalTri(k.RotationEnabled), Source: loc,
		})
		n.b.AddResource(key)
		raw, _ := json.Marshal(k.Policy)
		n.b.AddPolicy(&model.AttachedPolicy{Target: key.ID(), Doc: n.parse(raw, k.Metadata.Arn+"#key-policy", model.PolicyResource, &loc)})
	}
}

func (n *norm) buckets() {
	for _, b := range n.acct.Buckets {
		arn := "arn:" + n.acct.Partition + ":s3:::" + b.Name
		loc := apiLoc(arn, "s3:GetBucketPolicy")
		enc := model.Encryption{} // unknown unless get-bucket-encryption was collected
		if b.Encryption != nil {
			enc = model.Encryption{Type: b.Encryption.SSEAlgorithm, KeyARN: b.Encryption.KMSMasterKeyID}
		}
		restrict := model.Unknown
		if b.PublicAccessBlock != nil {
			restrict = model.TriOf(b.PublicAccessBlock.RestrictPublicBuckets)
		}
		res := model.NewResource(&model.ResourceInput{
			Kind: model.KindS3Bucket, ARN: arn, Account: n.acct.ID, Region: b.Region, Tags: tagMap(b.Tags),
			Encryption: enc, S3: model.S3Settings{RestrictPublicBuckets: restrict}, Source: loc,
		})
		n.b.AddResource(res)
		if b.Policy != "" {
			raw, _ := json.Marshal(b.Policy)
			n.b.AddPolicy(&model.AttachedPolicy{Target: res.ID(), Doc: n.parse(raw, arn+"#bucket-policy", model.PolicyResource, &loc)})
		}
	}
}

func (n *norm) clusters() {
	for _, c := range n.acct.Clusters {
		loc := apiLoc(c.Arn, "eks:DescribeCluster")
		n.b.AddCluster(&model.Cluster{Name: c.Name, ARN: c.Arn, Account: n.acct.ID, Region: c.Region, OIDCIssuer: c.OIDCIssuer, Source: loc})
		for _, a := range c.PodIdentity {
			n.b.AddPodIdentity(&model.PodIdentityAssociation{
				Cluster: a.ClusterName, Namespace: a.Namespace, ServiceAccount: a.ServiceAccount, RoleARN: a.RoleArn,
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
