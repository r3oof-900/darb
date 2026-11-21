package awslive

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/r3oof-900/clapa/internal/collect/awsraw"
)

// kms lists the region's keys and aliases; for each key it reads its
// metadata, its key policy, and (customer managed keys) rotation and tags.
func (a *account) kms(ctx context.Context, c *Clients, region string) error {
	var aliases []awsraw.Alias
	err := a.call(ctx, "kms", region, "ListAliases", "", func(ctx context.Context) error {
		p := kms.NewListAliasesPaginator(c.KMS, &kms.ListAliasesInput{})
		for p.HasMorePages() {
			page, perr := p.NextPage(ctx)
			if perr != nil {
				return perr
			}
			for _, al := range page.Aliases {
				aliases = append(aliases, awsraw.Alias{Region: region, AliasName: aws.ToString(al.AliasName), AliasArn: aws.ToString(al.AliasArn), TargetKeyID: aws.ToString(al.TargetKeyId)})
			}
		}
		return nil
	})
	if done(err) {
		return err
	}
	var keys []*awsraw.Key
	err = a.call(ctx, "kms", region, "ListKeys", "", func(ctx context.Context) error {
		p := kms.NewListKeysPaginator(c.KMS, &kms.ListKeysInput{})
		for p.HasMorePages() {
			page, perr := p.NextPage(ctx)
			if perr != nil {
				return perr
			}
			for _, k := range page.Keys {
				keys = append(keys, &awsraw.Key{Region: region, Metadata: awsraw.KeyMetadata{KeyID: aws.ToString(k.KeyId), Arn: aws.ToString(k.KeyArn)}})
			}
		}
		return nil
	})
	if done(err) {
		return err
	}
	if err := group(ctx, a, keys, func(ctx context.Context, k *awsraw.Key) error { return a.key(ctx, c, k) }); err != nil {
		return err
	}
	a.mu.Lock()
	a.acct.Keys = append(a.acct.Keys, keys...)
	a.acct.Aliases = append(a.acct.Aliases, aliases...)
	a.mu.Unlock()
	return nil
}

func (a *account) key(ctx context.Context, c *Clients, k *awsraw.Key) error {
	id, region := k.Metadata.KeyID, k.Region
	err := a.call(ctx, "kms", region, "DescribeKey", id, func(ctx context.Context) error {
		out, derr := c.KMS.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &id})
		if derr == nil && out.KeyMetadata != nil {
			m := out.KeyMetadata
			k.Metadata = awsraw.KeyMetadata{KeyID: aws.ToString(m.KeyId), Arn: aws.ToString(m.Arn), KeyManager: string(m.KeyManager), KeyState: string(m.KeyState)}
		}
		return derr
	})
	if done(err) {
		return err
	}
	err = a.call(ctx, "kms", region, "GetKeyPolicy", id, func(ctx context.Context) error {
		out, perr := c.KMS.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: &id, PolicyName: aws.String("default")})
		if perr == nil {
			k.Policy = aws.ToString(out.Policy)
		}
		return perr
	})
	if done(err) {
		return err
	}
	if k.Metadata.KeyManager == string(kmstypes.KeyManagerTypeAws) {
		// AWS managed keys: AWS rotates them (the normalizer applies that
		// documented default) and the account cannot tag them.
		return nil
	}
	return a.customerKey(ctx, c, k)
}

// customerKey reads a customer managed key's rotation status and tags.
func (a *account) customerKey(ctx context.Context, c *Clients, k *awsraw.Key) error {
	id, region := k.Metadata.KeyID, k.Region
	err := a.call(ctx, "kms", region, "GetKeyRotationStatus", id, func(ctx context.Context) error {
		out, rerr := c.KMS.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: &id})
		if rerr == nil {
			k.RotationEnabled = aws.Bool(out.KeyRotationEnabled)
		}
		return rerr
	})
	if done(err) {
		return err
	}
	return a.call(ctx, "kms", region, "ListResourceTags", id, func(ctx context.Context) error {
		tags := []awsraw.Tag{}
		p := kms.NewListResourceTagsPaginator(c.KMS, &kms.ListResourceTagsInput{KeyId: &id})
		for p.HasMorePages() {
			page, perr := p.NextPage(ctx)
			if perr != nil {
				return perr
			}
			for _, t := range page.Tags {
				tags = append(tags, awsraw.Tag{Key: aws.ToString(t.TagKey), Value: aws.ToString(t.TagValue)})
			}
		}
		k.Tags = tags
		return nil
	})
}

// eks lists the region's clusters; for each it reads the cluster (OIDC
// issuer) and its Pod Identity associations.
func (a *account) eks(ctx context.Context, c *Clients, region string) error {
	var names []string
	err := a.call(ctx, "eks", region, "ListClusters", "", func(ctx context.Context) error {
		p := eks.NewListClustersPaginator(c.EKS, &eks.ListClustersInput{})
		for p.HasMorePages() {
			page, perr := p.NextPage(ctx)
			if perr != nil {
				return perr
			}
			names = append(names, page.Clusters...)
		}
		return nil
	})
	if done(err) {
		return err
	}
	clusters := make([]*awsraw.Cluster, len(names))
	for i, n := range names {
		clusters[i] = &awsraw.Cluster{Region: region, Name: n}
	}
	if err := group(ctx, a, clusters, func(ctx context.Context, cl *awsraw.Cluster) error { return a.cluster(ctx, c, cl) }); err != nil {
		return err
	}
	a.mu.Lock()
	a.acct.Clusters = append(a.acct.Clusters, clusters...)
	a.mu.Unlock()
	return nil
}

func (a *account) cluster(ctx context.Context, c *Clients, cl *awsraw.Cluster) error {
	err := a.call(ctx, "eks", cl.Region, "DescribeCluster", cl.Name, func(ctx context.Context) error {
		out, derr := c.EKS.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &cl.Name})
		if derr == nil && out.Cluster != nil {
			cl.Arn = aws.ToString(out.Cluster.Arn)
			if id := out.Cluster.Identity; id != nil && id.Oidc != nil {
				cl.OIDCIssuer = aws.ToString(id.Oidc.Issuer)
			}
		}
		return derr
	})
	if done(err) {
		return err
	}
	var ids []string
	err = a.call(ctx, "eks", cl.Region, "ListPodIdentityAssociations", cl.Name, func(ctx context.Context) error {
		p := eks.NewListPodIdentityAssociationsPaginator(c.EKS, &eks.ListPodIdentityAssociationsInput{ClusterName: &cl.Name})
		for p.HasMorePages() {
			page, perr := p.NextPage(ctx)
			if perr != nil {
				return perr
			}
			for _, s := range page.Associations {
				ids = append(ids, aws.ToString(s.AssociationId))
			}
		}
		return nil
	})
	if done(err) {
		return err
	}
	for _, id := range ids {
		if err := a.association(ctx, c, cl, id); done(err) {
			return err
		}
	}
	return nil
}

func (a *account) association(ctx context.Context, c *Clients, cl *awsraw.Cluster, id string) error {
	return a.call(ctx, "eks", cl.Region, "DescribePodIdentityAssociation", cl.Name+"/"+id, func(ctx context.Context) error {
		out, err := c.EKS.DescribePodIdentityAssociation(ctx, &eks.DescribePodIdentityAssociationInput{ClusterName: &cl.Name, AssociationId: &id})
		if err != nil || out.Association == nil {
			return err
		}
		s := out.Association
		cl.PodIdentity = append(cl.PodIdentity, awsraw.PodIdentityAssociation{
			ClusterName: aws.ToString(s.ClusterName), Namespace: aws.ToString(s.Namespace), ServiceAccount: aws.ToString(s.ServiceAccount),
			RoleArn: aws.ToString(s.RoleArn), AssociationArn: aws.ToString(s.AssociationArn), TargetRoleArn: aws.ToString(s.TargetRoleArn),
			DisableSessionTags: s.DisableSessionTags,
		})
		return nil
	})
}
