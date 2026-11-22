package pseudonymize

import (
	"strings"
	"testing"
)

// Identifiers leave as tokens and come back exactly; the same identifier
// is always the same token; text around them is kept.
func TestRoundTrip(t *testing.T) {
	in := "k8s:arn:aws:eks:us-east-1:111122223333:cluster/prod/payments/Deployment/api reaches " +
		"arn:aws:s3:::acme-customer-pii through arn:aws:iam::111122223333:role/payments-api " +
		"(account 111122223333, and again arn:aws:iam::111122223333:role/payments-api)"
	m := New()
	out := m.Apply(in)
	for _, leak := range []string{"111122223333", "acme-customer-pii", "payments-api", "arn:aws", "k8s:arn"} {
		if strings.Contains(out, leak) {
			t.Fatalf("%q left as is: %s", leak, out)
		}
	}
	if strings.Count(out, "arn-0002") != 2 {
		t.Errorf("the same ARN is not the same token: %s", out)
	}
	if !strings.Contains(out, " reaches ") || !strings.Contains(out, "(account account-0001,") {
		t.Errorf("text around identifiers changed: %s", out)
	}
	if got := m.Restore(out); got != in {
		t.Fatalf("round trip:\n got %s\nwant %s", got, in)
	}
	if m.Apply(out) != out {
		t.Error("tokens are pseudonymised again")
	}
}

// Ten and more tokens of a kind never collide with a prefix (arn-0001 in
// arn-0010).
func TestManyTokens(t *testing.T) {
	m := New()
	var b strings.Builder
	for i := range 12 {
		b.WriteString("arn:aws:s3:::bucket-" + strings.Repeat("x", i+1) + " ")
	}
	in := b.String()
	if got := m.Restore(m.Apply(in)); got != in {
		t.Fatalf("round trip with 12 tokens:\n got %s\nwant %s", got, in)
	}
	if m.Len() != 12 {
		t.Errorf("%d identifiers mapped, want 12", m.Len())
	}
}
