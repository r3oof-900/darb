package model

import "testing"

func TestClusterKeys(t *testing.T) {
	u := UnresolvedPlaceholder("x")
	for _, c := range []struct{ partition, region, account, name, want string }{
		{"", "eu-west-1", "111122223333", "prod", "arn:aws:eks:eu-west-1:111122223333:cluster/prod"},
		{"aws-cn", "cn-north-1", "111122223333", "prod", "arn:aws-cn:eks:cn-north-1:111122223333:cluster/prod"},
		{"aws", "", "111122223333", "prod", ""},
		{"aws", "eu-west-1", "", "prod", ""},
		{"aws", "eu-west-1", "111122223333", "", ""},
		{"aws", u, "111122223333", "prod", ""},
		{"aws", "eu-west-1", u, "prod", ""},
		{"aws", "eu-west-1", "111122223333", u, ""},
	} {
		if got := EKSClusterARN(c.partition, c.region, c.account, c.name); got != c.want {
			t.Errorf("EKSClusterARN(%q, %q, %q, %q) = %q", c.partition, c.region, c.account, c.name, got)
		}
	}
	arn := "arn:aws:eks:eu-west-1:111122223333:cluster/prod"
	if ClusterKey(arn, "prod") != arn || ClusterKey("", "prod") != "prod" || ClusterKey("arn:aws:eks:"+u, "prod") != "prod" {
		t.Error("ClusterKey")
	}
	if (&Cluster{Name: "prod", ARN: arn}).Key() != arn || (&Cluster{Name: "prod"}).Key() != "prod" {
		t.Error("Cluster.Key")
	}
	for s, want := range map[string]bool{
		arn: true, "prod": false, "arn:aws:iam::111122223333:role/x": false, "arn:aws:eks:eu-west-1:111122223333:nodegroup/p/n": false, "arn:aws:eks": false,
	} {
		if IsClusterARN(s) != want {
			t.Errorf("IsClusterARN(%q)", s)
		}
	}
}

func TestEncryptionContextKey(t *testing.T) {
	for arn, want := range map[string]string{ //nolint:gosec // G101: condition key names, not credentials.
		"arn:aws:secretsmanager:us-east-1:1:secret:a-b": "kms:EncryptionContext:SecretARN",
		"arn:aws:ssm:us-east-1:1:parameter/a/b":         "kms:EncryptionContext:PARAMETER_ARN",
		"arn:aws:ssm:us-east-1:1:document/x":            "kms:EncryptionContext:aws:s3:arn",
		"arn:aws:s3:::bucket":                           "kms:EncryptionContext:aws:s3:arn",
		"k8s:prod/ns/Secret/x:secretsmanager:":          "kms:EncryptionContext:aws:s3:arn",
		"k8s:prod/ns/Secret/x:ssm::parameter/":          "kms:EncryptionContext:aws:s3:arn",
	} {
		if got := EncryptionContextKey(arn); got != want {
			t.Errorf("%s: %s", arn, got)
		}
	}
}
