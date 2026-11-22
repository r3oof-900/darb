package awslive

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/r3oof-900/darb/internal/collect/awsraw"
)

// secrets lists the region's secrets (metadata: ARN, name, KMS key, tags;
// list-secrets never returns a value) and reads each one's resource policy.
func (a *account) secrets(ctx context.Context, c *Clients, region string) error {
	var list []*awsraw.Secret
	err := a.call(ctx, "secretsmanager", region, "ListSecrets", "", func(ctx context.Context) error {
		p := secretsmanager.NewListSecretsPaginator(c.Secrets, &secretsmanager.ListSecretsInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return err
			}
			for i := range page.SecretList {
				s := &page.SecretList[i]
				sec := &awsraw.Secret{Region: region, ARN: aws.ToString(s.ARN), Name: aws.ToString(s.Name), KMSKeyID: aws.ToString(s.KmsKeyId), Tags: []awsraw.Tag{}}
				for _, t := range s.Tags {
					sec.Tags = append(sec.Tags, awsraw.Tag{Key: aws.ToString(t.Key), Value: aws.ToString(t.Value)})
				}
				list = append(list, sec)
			}
		}
		return nil
	})
	if done(err) {
		return err
	}
	err = group(ctx, a, list, func(ctx context.Context, s *awsraw.Secret) error {
		cerr := a.call(ctx, "secretsmanager", region, "GetResourcePolicy", s.ARN, func(ctx context.Context) error {
			out, gerr := c.Secrets.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: &s.ARN})
			if gerr == nil {
				s.Policy = aws.ToString(out.ResourcePolicy) // nil: no resource policy
			}
			return gerr
		})
		s.PolicyFailed = cerr != nil
		return cerr
	})
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.acct.Secrets = append(a.acct.Secrets, list...)
	a.mu.Unlock()
	return nil
}

// ssm describes the region's parameters (metadata only: describe-parameters
// never returns a value), then reads each one's tags and, for an advanced
// parameter, its resource policies.
func (a *account) ssm(ctx context.Context, c *Clients, region string) error {
	var list []*awsraw.Parameter
	err := a.call(ctx, "ssm", region, "DescribeParameters", "", func(ctx context.Context) error {
		p := ssm.NewDescribeParametersPaginator(c.SSM, &ssm.DescribeParametersInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return err
			}
			for i := range page.Parameters {
				m := &page.Parameters[i]
				list = append(list, &awsraw.Parameter{
					Region: region, Name: aws.ToString(m.Name), ARN: aws.ToString(m.ARN), Type: string(m.Type),
					KeyID: aws.ToString(m.KeyId), Tier: string(m.Tier),
				})
			}
		}
		return nil
	})
	if done(err) {
		return err
	}
	err = group(ctx, a, list, func(ctx context.Context, p *awsraw.Parameter) error { return a.parameter(ctx, c, p) })
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.acct.Params = append(a.acct.Params, list...)
	a.mu.Unlock()
	return nil
}

func (a *account) parameter(ctx context.Context, c *Clients, p *awsraw.Parameter) error {
	err := a.call(ctx, "ssm", p.Region, "ListTagsForResource", p.ARN, func(ctx context.Context) error {
		out, err := c.SSM.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingParameter, ResourceId: &p.Name})
		if err == nil {
			p.Tags = []awsraw.Tag{}
			for _, t := range out.TagList {
				p.Tags = append(p.Tags, awsraw.Tag{Key: aws.ToString(t.Key), Value: aws.ToString(t.Value)})
			}
		}
		return err
	})
	if done(err) || p.Tier != string(ssmtypes.ParameterTierAdvanced) {
		return err // only advanced parameters can have a resource policy
	}
	err = a.call(ctx, "ssm", p.Region, "GetResourcePolicies", p.ARN, func(ctx context.Context) error {
		pg := ssm.NewGetResourcePoliciesPaginator(c.SSM, &ssm.GetResourcePoliciesInput{ResourceArn: &p.ARN})
		for pg.HasMorePages() {
			page, perr := pg.NextPage(ctx)
			if perr != nil {
				return perr
			}
			for _, rp := range page.Policies {
				p.Policies = append(p.Policies, aws.ToString(rp.Policy))
			}
		}
		return nil
	})
	p.PolicyFailed = err != nil
	return err
}
