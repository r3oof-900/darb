package redact

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// The samples are made at run time from parts, so that no secret-shaped
// string is committed (gitleaks guards the repository).
func rep(s string, n int) string { return strings.Repeat(s, n) }

// secretSamples: one sample per format, each in a sentence around it.
func secretSamples() map[string]string {
	hex := func(n int) string { return rep("a1", n/2) + rep("b", n%2) }
	b64 := func(n int) string { return rep("Q", n) }
	return map[string]string{
		"private-key":               "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIE" + b64(60) + "\n-----END " + "RSA PRIVATE KEY-----",
		"aws-access-key-id":         "id " + "AK" + "IA" + rep("Q", 16) + " used",
		"aws-secret-access-key":     "aws_secret_access_key = " + b64(40),
		"aws-session-token":         "aws_session_token: " + b64(120),
		"anthropic-api-key":         "key sk-" + "ant-api03-" + rep("x", 90),
		"openai-api-key":            "key sk-" + "proj-" + rep("x", 48),
		"github-token":              "gh" + "p_" + rep("A", 36),
		"github-fine-grained-token": "github" + "_pat_" + rep("A", 82),
		"gitlab-token":              "glp" + "at-" + rep("a", 20),
		"gitlab-runner-token":       "glr" + "t-" + rep("a", 20),
		"slack-token":               "xo" + "xb-" + rep("1", 12) + "-abc",
		"slack-webhook":             "https://hooks.slack.com/services/" + "T0AAAA/B0BBBB/" + rep("c", 24),
		"discord-webhook":           "https://discord.com/api/webhooks/" + "123/" + rep("d", 64),
		"stripe-key":                "s" + "k_live_" + rep("e", 24),
		"google-api-key":            "AI" + "za" + rep("f", 35),
		"google-oauth-secret":       "GOC" + "SPX-" + rep("g", 28),
		"gcp-service-account-key":   `{"private_key_id": "` + hex(40) + `"}`,
		"azure-storage-key":         "DefaultEndpointsProtocol=https;" + "Account" + "Key=" + b64(86) + "==",
		"azure-sas-signature":       "https://a.blob.core.windows.net/c?sv=1&s" + "ig=" + b64(44) + "%3D",
		"azure-client-secret":       "abc" + "8Q~" + rep("h", 32),
		"twilio-api-key":            "S" + "K" + hex(32),
		"sendgrid-api-key":          "S" + "G." + rep("i", 22) + "." + rep("j", 43),
		"mailgun-api-key":           "ke" + "y-" + hex(32),
		"mailchimp-api-key":         hex(32) + "-us" + "12",
		"npm-token":                 "np" + "m_" + rep("k", 36),
		"pypi-token":                "py" + "pi-AgEIcHlwaS5vcmc" + rep("l", 60),
		"docker-hub-token":          "dckr" + "_pat_" + rep("m", 27),
		"digitalocean-token":        "do" + "p_v1_" + hex(64),
		"shopify-token":             "shp" + "at_" + hex(32),
		"square-token":              "sq0" + "atp-" + rep("n", 22),
		"atlassian-api-token":       "ATA" + "TT3" + rep("o", 190),
		"hashicorp-vault-token":     "hv" + "s." + rep("p", 24),
		"terraform-cloud-token":     rep("q", 14) + ".atlas" + "v1." + rep("r", 64),
		"new-relic-key":             "NR" + "AK-" + rep("S", 27),
		"grafana-token":             "gl" + "sa_" + rep("t", 32),
		"sentry-token":              "sntr" + "ys_" + rep("u", 40),
		"linear-api-key":            "lin" + "_api_" + rep("v", 40),
		"doppler-token":             "dp" + ".pt." + rep("w", 40),
		"pulumi-token":              "pu" + "l-" + hex(40),
		"postman-api-key":           "PM" + "AK-" + hex(24) + "-" + hex(34),
		"telegram-bot-token":        "123456789" + ":AA" + rep("x", 33),
		"age-secret-key":            "AGE-SECRET" + "-KEY-1" + rep("Q", 58),
		"jwt":                       "ey" + "J" + rep("a", 12) + ".ey" + "J" + rep("b", 12) + "." + rep("c", 12),
		"kubernetes-sa-token":       "k8s-aws" + "-v1." + rep("y", 44),
		"url-password":              "postgres://admin:" + "hunter" + "2pass@db.internal:5432/app",
		"password-assignment":       "pass" + "word = " + "Corr3ctHorse",
		"secret-assignment":         "client" + "_secret: " + rep("Z", 20),
		"bearer-token":              "Authorization: Bear" + "er " + rep("z", 30),
	}
}

// Every format is redacted, and there are at least 40 of them.
func TestEveryFormatIsRedacted(t *testing.T) {
	samples := secretSamples()
	if len(Formats()) < 40 {
		t.Fatalf("%d formats, want at least 40 (DESIGN.md §10)", len(Formats()))
	}
	for _, name := range Formats() {
		s, ok := samples[name]
		if !ok {
			t.Errorf("format %s has no sample", name)
			continue
		}
		out := Redact(s)
		if out == s || !strings.Contains(out, "[REDACTED:") {
			t.Errorf("%s: not redacted: %q", name, out)
		}
		if Redact(out) != out {
			t.Errorf("%s: redacting twice changes the text", name)
		}
	}
}

// Look-alikes that are not secrets stay as they are: identities, ARNs,
// digests, policy text, Terraform references, the report's own words.
func TestFalsePositivesStay(t *testing.T) {
	corpus := []string{
		"arn:aws:iam::111122223333:role/payments-api",
		"arn:aws:kms:us-east-1:111122223333:key/0b1c2d3e-0000-4000-8000-000000000001",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-aaaaaa",
		"k8s:arn:aws:eks:us-east-1:111122223333:cluster/prod/payments/Deployment/api",
		"sha256:0ed98c0c9a38485934be3bd195091a715faa06b5e984a4d6fa9e8d34982928d0",
		"e2ac4b3dabca122c3a261f0294a4410406f2ca6c3d6a75874130816633cc97c8",
		"aws_iam_role_policy.payments_api DecryptAnything",
		`Condition = { StringEquals = { "kms:EncryptionContext:aws:s3:arn" = var.pii_bucket_arn } }`,
		"password = var.db_password",
		"secret_key = ${clapa:unresolved:var.secret}",
		"api_key: ${API_KEY}",
		"CLAPA-PATH-001 A workload can read crown-jewel data",
		"system:serviceaccount:payments:api",
		"https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html",
		"oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E",
		"the token is mounted (automountServiceAccountToken: true)",
		"Bearer of bad news",
		"sk-ant-short",
		"ghp_short",
		"tf-aws_kms_key.pii",
		"2026-11-22T00:00:00Z",
		"0b1c2d3e-0000-4000-8000-000000000001",
		"s3:GetObject on arn:aws:s3:::acme-customer-pii/*",
		"eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/app",
	}
	for _, s := range corpus {
		if got := Redact(s); got != s {
			t.Errorf("not a secret, but redacted: %q -> %q", s, got)
		}
	}
}

// Only the secret goes: the key word, the URL, the sentence stay.
func TestOnlyTheSecretGoes(t *testing.T) {
	s := secretSamples()["url-password"]
	if got := Redact(s); got != "postgres://admin:[REDACTED:url-password]@db.internal:5432/app" {
		t.Errorf("url password: %q", got)
	}
	if got := Redact("id " + "AK" + "IA" + rep("Q", 16) + " used"); got != "id [REDACTED:aws-access-key-id] used" {
		t.Errorf("sentence around a key: %q", got)
	}
}

// The log handler redacts the message, string attributes, groups, and
// every attribute whose key names a secret.
func TestHandler(t *testing.T) {
	var b bytes.Buffer
	log := slog.New(NewHandler(slog.NewJSONHandler(&b, nil)))
	key := "AK" + "IA" + rep("Q", 16)
	log.With("password", "x").WithGroup("g").Info("using "+key, "detail", "key "+key, "n", 3,
		slog.Group("inner", "api_key", "whatever", "note", key))
	out := b.String()
	if strings.Contains(out, key) || strings.Contains(out, `"whatever"`) || strings.Contains(out, `"x"`) {
		t.Fatalf("a secret reached the log: %s", out)
	}
	for _, want := range []string{"[REDACTED:aws-access-key-id]", "[REDACTED:password]", "[REDACTED:api_key]", `"n":3`} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s: %s", want, out)
		}
	}
}
