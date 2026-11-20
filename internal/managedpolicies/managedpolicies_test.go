package managedpolicies

import (
	"strings"
	"testing"
)

func TestSnapshot(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if s.SnapshotDate == "" || !strings.Contains(s.Source, "docs.aws.amazon.com") {
		t.Error("the snapshot must say when and where it came from")
	}
	p, ok := s.Lookup("arn:aws:iam::aws:policy/AdministratorAccess")
	if !ok || p.Version != "v1" || !strings.Contains(string(p.Document), `"Action": "*"`) {
		t.Fatalf("AdministratorAccess: %+v", p)
	}
	if _, ok := s.Lookup("arn:aws:iam::aws:policy/NotInSnapshot"); ok {
		t.Error("unknown policies are not guessed")
	}
	for arn, want := range map[string]bool{
		"arn:aws:iam::aws:policy/ReadOnlyAccess": true,
		"arn:aws-cn:iam::aws:policy/x":           true,
		"arn:aws:iam::111122223333:policy/mine":  false,
		"arn:aws:iam::aws:policy/":               false,
	} {
		if IsAWSManaged(arn) != want {
			t.Errorf("IsAWSManaged(%q) = %v", arn, !want)
		}
	}
}
