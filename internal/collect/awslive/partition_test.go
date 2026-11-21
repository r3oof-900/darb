package awslive

import "testing"

func TestPartitionOf(t *testing.T) {
	for in, want := range map[string]string{
		"arn:aws-cn:sts::111122223333:assumed-role/a/b": "aws-cn", "arn:aws-us-gov:iam::1:user/x": "aws-us-gov", "": "aws", "arn::x": "aws",
	} {
		if got := partitionOf(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}
