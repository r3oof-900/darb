package awslive

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/r3oof-900/clapa/internal/collect/awsraw"
)

// iam reads every page of GetAccountAuthorizationDetails (users, groups,
// roles and customer managed policies with all their versions). The SDK
// output is re-encoded as the API's JSON, which awsraw is shaped after.
func (a *account) iam(ctx context.Context, c *Clients) error {
	details := &awsraw.AuthorizationDetails{}
	err := a.call(ctx, "iam", "", "GetAccountAuthorizationDetails", "", func(ctx context.Context) error {
		p := iam.NewGetAccountAuthorizationDetailsPaginator(c.IAM, &iam.GetAccountAuthorizationDetailsInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return err
			}
			var part awsraw.AuthorizationDetails
			if err := reencode(page, &part); err != nil {
				return err
			}
			details.UserDetailList = append(details.UserDetailList, part.UserDetailList...)
			details.GroupDetailList = append(details.GroupDetailList, part.GroupDetailList...)
			details.RoleDetailList = append(details.RoleDetailList, part.RoleDetailList...)
			details.Policies = append(details.Policies, part.Policies...)
		}
		return nil
	})
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.acct.Auth = details
	a.mu.Unlock()
	return nil
}

// reencode converts an SDK output struct to the API's JSON shape. The SDK
// structs carry the API's member names, which awsraw's json tags use;
// policy documents stay URL-encoded strings, which the normalizer decodes.
func reencode(v, into any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("re-encoding %T: %w", v, err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		return fmt.Errorf("re-encoding %T: %w", v, err)
	}
	return nil
}

// s3 lists the buckets and reads each one's location, policy, default
// encryption, Block Public Access and tags, from a client in its region.
func (a *account) s3(ctx context.Context, c *Clients) error {
	var buckets []*awsraw.Bucket
	err := a.call(ctx, "s3", "", "ListBuckets", "", func(ctx context.Context) error {
		p := s3.NewListBucketsPaginator(c.S3, &s3.ListBucketsInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return err
			}
			for _, b := range page.Buckets {
				buckets = append(buckets, &awsraw.Bucket{Name: aws.ToString(b.Name), Region: aws.ToString(b.BucketRegion)})
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := group(ctx, a, buckets, func(ctx context.Context, b *awsraw.Bucket) error { return a.bucket(ctx, c, b) }); err != nil {
		return err
	}
	a.mu.Lock()
	a.acct.Buckets = append(a.acct.Buckets, buckets...)
	a.mu.Unlock()
	return nil
}

func (a *account) bucket(ctx context.Context, home *Clients, b *awsraw.Bucket) error {
	if err := a.bucketRegion(ctx, home, b); done(err) {
		return err
	}
	c := home
	if b.Region != "" {
		c = a.o.Factory.Clients(a.target, b.Region)
	}
	for _, step := range []func(context.Context, *Clients, *awsraw.Bucket) error{
		a.bucketPolicy, a.bucketEncryption, a.bucketPublicAccessBlock, a.bucketTags,
	} {
		if err := step(ctx, c, b); done(err) {
			return err
		}
	}
	return nil
}

// bucketRegion: ListBuckets gives the region; otherwise GetBucketLocation,
// whose empty LocationConstraint means us-east-1.
func (a *account) bucketRegion(ctx context.Context, c *Clients, b *awsraw.Bucket) error {
	if b.Region != "" {
		return nil
	}
	return a.call(ctx, "s3", "", "GetBucketLocation", b.Name, func(ctx context.Context) error {
		out, err := c.S3.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: &b.Name})
		if err == nil {
			b.Region = cmp.Or(string(out.LocationConstraint), "us-east-1")
		}
		return err
	})
}

func (a *account) bucketPolicy(ctx context.Context, c *Clients, b *awsraw.Bucket) error {
	err := a.call(ctx, "s3", b.Region, "GetBucketPolicy", b.Name, func(ctx context.Context) error {
		out, err := c.S3.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &b.Name})
		switch {
		case isCode(err, "NoSuchBucketPolicy"):
			return nil // no policy: an answer, not a failure
		case err == nil:
			b.Policy = aws.ToString(out.Policy)
		}
		return err
	})
	b.PolicyFailed = err != nil
	return err
}

func (a *account) bucketEncryption(ctx context.Context, c *Clients, b *awsraw.Bucket) error {
	return a.call(ctx, "s3", b.Region, "GetBucketEncryption", b.Name, func(ctx context.Context) error {
		out, err := c.S3.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &b.Name})
		if err != nil || out.ServerSideEncryptionConfiguration == nil || len(out.ServerSideEncryptionConfiguration.Rules) == 0 {
			return err
		}
		r := out.ServerSideEncryptionConfiguration.Rules[0]
		b.Encryption = &awsraw.Encryption{BucketKeyEnabled: r.BucketKeyEnabled}
		if d := r.ApplyServerSideEncryptionByDefault; d != nil {
			b.Encryption.SSEAlgorithm, b.Encryption.KMSMasterKeyID = string(d.SSEAlgorithm), aws.ToString(d.KMSMasterKeyID)
		}
		return nil
	})
}

// bucketPublicAccessBlock: a bucket with no configuration of its own has
// every setting off at the bucket level (account-level Block Public Access
// is not collected; DESIGN.md 4.4).
func (a *account) bucketPublicAccessBlock(ctx context.Context, c *Clients, b *awsraw.Bucket) error {
	return a.call(ctx, "s3", b.Region, "GetPublicAccessBlock", b.Name, func(ctx context.Context) error {
		out, err := c.S3.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &b.Name})
		switch {
		case isCode(err, "NoSuchPublicAccessBlockConfiguration"):
			b.PublicAccessBlock = &awsraw.PublicAccessBlock{}
			return nil
		case err != nil || out.PublicAccessBlockConfiguration == nil:
			return err
		}
		p := out.PublicAccessBlockConfiguration
		b.PublicAccessBlock = &awsraw.PublicAccessBlock{
			BlockPublicAcls: aws.ToBool(p.BlockPublicAcls), IgnorePublicAcls: aws.ToBool(p.IgnorePublicAcls),
			BlockPublicPolicy: aws.ToBool(p.BlockPublicPolicy), RestrictPublicBuckets: aws.ToBool(p.RestrictPublicBuckets),
		}
		return nil
	})
}

func (a *account) bucketTags(ctx context.Context, c *Clients, b *awsraw.Bucket) error {
	return a.call(ctx, "s3", b.Region, "GetBucketTagging", b.Name, func(ctx context.Context) error {
		out, err := c.S3.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &b.Name})
		switch {
		case isCode(err, "NoSuchTagSet"):
			b.Tags = []awsraw.Tag{}
			return nil
		case err != nil:
			return err
		}
		b.Tags = []awsraw.Tag{}
		for _, t := range out.TagSet {
			b.Tags = append(b.Tags, awsraw.Tag{Key: aws.ToString(t.Key), Value: aws.ToString(t.Value)})
		}
		return nil
	})
}
