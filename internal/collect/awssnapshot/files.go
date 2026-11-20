package awssnapshot

import "github.com/r3oof-900/clapa/internal/collect/awsraw"

func (r *reader) bucketFile(b *awsraw.Bucket, f, name string) error {
	switch name {
	case "get-bucket-policy.json":
		var v struct {
			Policy string `json:"Policy"`
		}
		err := r.json(f, &v)
		b.Policy = v.Policy
		return err
	case "get-bucket-encryption.json":
		var v struct {
			ServerSideEncryptionConfiguration struct {
				Rules []struct {
					ApplyServerSideEncryptionByDefault struct {
						SSEAlgorithm   string `json:"SSEAlgorithm"`
						KMSMasterKeyID string `json:"KMSMasterKeyID"`
					} `json:"ApplyServerSideEncryptionByDefault"`
				} `json:"Rules"`
			} `json:"ServerSideEncryptionConfiguration"`
		}
		err := r.json(f, &v)
		if rules := v.ServerSideEncryptionConfiguration.Rules; err == nil && len(rules) > 0 {
			d := rules[0].ApplyServerSideEncryptionByDefault
			b.Encryption = &awsraw.Encryption{SSEAlgorithm: d.SSEAlgorithm, KMSMasterKeyID: d.KMSMasterKeyID}
		}
		return err
	case "get-public-access-block.json":
		var v struct {
			Config awsraw.PublicAccessBlock `json:"PublicAccessBlockConfiguration"`
		}
		err := r.json(f, &v)
		b.PublicAccessBlock = &v.Config
		return err
	case "get-bucket-tagging.json":
		var v struct {
			TagSet []awsraw.Tag `json:"TagSet"`
		}
		err := r.json(f, &v)
		b.Tags = v.TagSet
		return err
	case "get-bucket-location.json":
		var v struct {
			LocationConstraint *string `json:"LocationConstraint"`
		}
		err := r.json(f, &v)
		b.Region = "us-east-1" // a null LocationConstraint means us-east-1
		if v.LocationConstraint != nil && *v.LocationConstraint != "" {
			b.Region = *v.LocationConstraint
		}
		return err
	}
	return errUnknownFile
}

func (r *reader) keyFile(k *awsraw.Key, f, name string) error {
	switch name {
	case "describe-key.json":
		var v struct {
			KeyMetadata awsraw.KeyMetadata `json:"KeyMetadata"`
		}
		err := r.json(f, &v)
		if err == nil {
			k.Metadata = v.KeyMetadata
		}
		return err
	case "get-key-policy.json":
		var v struct {
			Policy string `json:"Policy"`
		}
		err := r.json(f, &v)
		k.Policy = v.Policy
		return err
	case "get-key-rotation-status.json":
		var v struct {
			KeyRotationEnabled bool `json:"KeyRotationEnabled"`
		}
		err := r.json(f, &v)
		if err == nil {
			k.RotationEnabled = &v.KeyRotationEnabled
		}
		return err
	}
	return errUnknownFile
}

func (r *reader) clusterFile(c *awsraw.Cluster, f string, rest []string) error {
	switch {
	case len(rest) == 1 && rest[0] == "describe-cluster.json":
		var v struct {
			Cluster struct {
				Name     string `json:"name"`
				Arn      string `json:"arn"`
				Identity struct {
					OIDC struct {
						Issuer string `json:"issuer"`
					} `json:"oidc"`
				} `json:"identity"`
			} `json:"cluster"`
		}
		err := r.json(f, &v)
		c.Arn, c.OIDCIssuer = v.Cluster.Arn, v.Cluster.Identity.OIDC.Issuer
		return err
	case len(rest) == 2 && rest[0] == "pod-identity":
		var v struct {
			Association awsraw.PodIdentityAssociation `json:"association"`
		}
		err := r.json(f, &v)
		if err == nil {
			c.PodIdentity = append(c.PodIdentity, v.Association)
		}
		return err
	}
	return errUnknownFile
}
