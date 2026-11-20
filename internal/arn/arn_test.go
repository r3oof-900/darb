package arn

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in      string
		want    ARN
		wantErr bool
	}{
		{in: "arn:aws:s3:::bucket", want: ARN{"aws", "s3", "", "", "bucket"}},
		{in: "arn:aws:s3:::bucket/key:with:colons", want: ARN{"aws", "s3", "", "", "bucket/key:with:colons"}},
		{in: "arn:aws:iam::111122223333:role/path/r", want: ARN{"aws", "iam", "", "111122223333", "role/path/r"}},
		{in: "arn:aws-cn:kms:cn-north-1:111122223333:key/abc", want: ARN{"aws-cn", "kms", "cn-north-1", "111122223333", "key/abc"}},
		{in: "arn:aws:sts::111122223333:assumed-role/r/s", want: ARN{"aws", "sts", "", "111122223333", "assumed-role/r/s"}},
		{in: "arn:aws:s3::", wantErr: true},
		{in: "arn::s3:::b", wantErr: true},
		{in: "arn:aws::::b", wantErr: true},
		{in: "urn:aws:s3:::b", wantErr: true},
		{in: "", wantErr: true},
		{in: "*", wantErr: true},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if c.wantErr {
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("Parse(%q) error = %v, want ErrInvalid", c.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q) unexpected error %v", c.in, err)
			continue
		}
		if *got != c.want {
			t.Errorf("Parse(%q) = %+v, want %+v", c.in, *got, c.want)
		}
		if got.String() != c.in {
			t.Errorf("String() = %q, want round trip %q", got.String(), c.in)
		}
	}
}

func TestAccountHelpers(t *testing.T) {
	root, err := Parse(AccountRoot("aws", "111122223333"))
	if err != nil || !root.IsAccountRoot() {
		t.Fatalf("AccountRoot not recognised: %v %v", root, err)
	}
	for _, s := range []string{
		"arn:aws:iam::111122223333:user/root",
		"arn:aws:iam:us-east-1:111122223333:root",
		"arn:aws:iam::12345:root",
		"arn:aws:sts::111122223333:root",
	} {
		a, err := Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		if a.IsAccountRoot() {
			t.Errorf("%s must not be an account root", s)
		}
	}
	for s, want := range map[string]bool{
		"111122223333": true, "11112222333": false, "1111222233334": false, "11112222333a": false, "": false,
	} {
		if IsAccountID(s) != want {
			t.Errorf("IsAccountID(%q) = %v, want %v", s, !want, want)
		}
	}
}
