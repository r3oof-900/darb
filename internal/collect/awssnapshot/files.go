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
					BucketKeyEnabled *bool `json:"BucketKeyEnabled"`
				} `json:"Rules"`
			} `json:"ServerSideEncryptionConfiguration"`
		}
		err := r.json(f, &v)
		if rules := v.ServerSideEncryptionConfiguration.Rules; err == nil && len(rules) > 0 {
			d := rules[0].ApplyServerSideEncryptionByDefault
			b.Encryption = &awsraw.Encryption{SSEAlgorithm: d.SSEAlgorithm, KMSMasterKeyID: d.KMSMasterKeyID, BucketKeyEnabled: rules[0].BucketKeyEnabled}
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
	case "list-resource-tags.json":
		var v struct {
			Tags []struct {
				TagKey   string `json:"TagKey"`
				TagValue string `json:"TagValue"`
			} `json:"Tags"`
		}
		err := r.json(f, &v)
		k.Tags = []awsraw.Tag{}
		for _, t := range v.Tags {
			k.Tags = append(k.Tags, awsraw.Tag{Key: t.TagKey, Value: t.TagValue})
		}
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

func (r *reader) aliasFile(l *layout, region, f string) error {
	var v struct {
		Aliases []awsraw.Alias `json:"Aliases"`
	}
	err := r.json(f, &v)
	for _, al := range v.Aliases {
		al.Region = region
		l.aliases = append(l.aliases, al)
	}
	return err
}

func (r *reader) secretFile(s *awsraw.Secret, f, name string) error {
	switch name {
	case "describe-secret.json":
		var v struct {
			ARN      string       `json:"ARN"`
			KmsKeyID string       `json:"KmsKeyId"`
			Tags     []awsraw.Tag `json:"Tags"`
		}
		err := r.json(f, &v)
		s.ARN, s.KMSKeyID, s.Tags = v.ARN, v.KmsKeyID, v.Tags
		if s.Tags == nil && err == nil {
			s.Tags = []awsraw.Tag{}
		}
		return err
	case "get-resource-policy.json":
		var v struct {
			ResourcePolicy string `json:"ResourcePolicy"`
		}
		err := r.json(f, &v)
		s.Policy = v.ResourcePolicy
		return err
	}
	return errUnknownFile
}

func (r *reader) parameterFile(prm *awsraw.Parameter, f, name string) error {
	switch name {
	case "describe-parameters.json":
		var v struct {
			Parameters []struct {
				ARN   string `json:"ARN"`
				Type  string `json:"Type"`
				KeyID string `json:"KeyId"`
				Tier  string `json:"Tier"`
			} `json:"Parameters"`
		}
		err := r.json(f, &v)
		if err == nil && len(v.Parameters) == 1 {
			m := v.Parameters[0]
			prm.ARN, prm.Type, prm.KeyID, prm.Tier = m.ARN, m.Type, m.KeyID, m.Tier
		}
		return err
	case "list-tags-for-resource.json":
		var v struct {
			TagList []awsraw.Tag `json:"TagList"`
		}
		err := r.json(f, &v)
		prm.Tags = append([]awsraw.Tag{}, v.TagList...)
		return err
	case "get-resource-policies.json":
		var v struct {
			Policies []struct {
				Policy string `json:"Policy"`
			} `json:"Policies"`
		}
		err := r.json(f, &v)
		prm.Policies = []string{}
		for _, p := range v.Policies {
			prm.Policies = append(prm.Policies, p.Policy)
		}
		return err
	}
	return errUnknownFile
}
