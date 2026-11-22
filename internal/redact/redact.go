// Package redact finds secrets in strings and replaces them, before a string
// is logged or sent to an LLM provider (DESIGN.md §10, THREAT_MODEL.md).
// Every format is a precise pattern (a vendor prefix, a fixed shape, a key
// word next to the value): a false positive hides a name a reader needs,
// a false negative leaks a secret, and both are tested
// (redact_test.go: a corpus of each format and of look-alikes that are not
// secrets).
package redact

import (
	"regexp"
	"strings"
)

// Format is one kind of secret and how to find it.
type Format struct {
	Name string
	re   *regexp.Regexp
	// group: the submatch that is the secret (0: the whole match), so a
	// key word or a URL around it stays readable.
	group int
}

func f(name, pattern string) Format { return Format{Name: name, re: regexp.MustCompile(pattern)} }

func g(name, pattern string, group int) Format {
	return Format{Name: name, re: regexp.MustCompile(pattern), group: group}
}

// formats: specific prefixes first, then shapes, then key words.
var formats = []Format{
	f("private-key", `-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----`),
	f("aws-access-key-id", `\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|APKA|ASCA)[A-Z2-7]{16}\b`),
	g("aws-secret-access-key", `(?i)(aws_?secret_?access_?key|secretaccesskey)["'\s:=]+([A-Za-z0-9/+]{40})\b`, 2),
	g("aws-session-token", `(?i)(aws_?session_?token|sessiontoken)["'\s:=]+([A-Za-z0-9/+=]{100,})`, 2),
	f("anthropic-api-key", `\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b`),
	f("openai-api-key", `\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}\b`),
	f("github-token", `\bgh[pousr]_[A-Za-z0-9]{36,255}\b`),
	f("github-fine-grained-token", `\bgithub_pat_[A-Za-z0-9_]{82}\b`),
	f("gitlab-token", `\bglpat-[A-Za-z0-9_-]{20,}\b`),
	f("gitlab-runner-token", `\bglrt-[A-Za-z0-9_-]{20,}\b`),
	f("slack-token", `\bxox[abposr]-[A-Za-z0-9-]{10,}\b`),
	// search pattern used to find secrets inside free text; anchoring would stop it from matching mid-line
	f("slack-webhook", `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}`),
	// search pattern used to find secrets inside free text; anchoring would stop it from matching mid-line
	f("discord-webhook", `https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{60,}`),
	f("stripe-key", `\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b`),
	f("google-api-key", `\bAIza[0-9A-Za-z_-]{35}\b`),
	f("google-oauth-secret", `\bGOCSPX-[A-Za-z0-9_-]{28}\b`),
	g("gcp-service-account-key", `"private_key_id"\s*:\s*"([a-f0-9]{40})"`, 1),
	f("azure-storage-key", `(?i)AccountKey=[A-Za-z0-9+/]{86}==`),
	g("azure-sas-signature", `[?&]sig=([A-Za-z0-9%+/]{40,}(?:%3D|=){0,2})`, 1),
	f("azure-client-secret", `\b[A-Za-z0-9_~.-]{3}8Q~[A-Za-z0-9_~.-]{31,34}\b`),
	f("twilio-api-key", `\bSK[0-9a-f]{32}\b`),
	f("sendgrid-api-key", `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`),
	f("mailgun-api-key", `\bkey-[0-9a-f]{32}\b`),
	f("mailchimp-api-key", `\b[0-9a-f]{32}-us\d{1,2}\b`),
	f("npm-token", `\bnpm_[A-Za-z0-9]{36}\b`),
	f("pypi-token", `\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b`),
	f("docker-hub-token", `\bdckr_pat_[A-Za-z0-9_-]{27,}\b`),
	f("digitalocean-token", `\bdo[por]_v1_[a-f0-9]{64}\b`),
	f("shopify-token", `\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b`),
	f("square-token", `\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,43}\b`),
	f("atlassian-api-token", `\bATATT3[A-Za-z0-9_=-]{180,}\b`),
	f("hashicorp-vault-token", `\bhv[sbr]\.[A-Za-z0-9_-]{24,}\b`),
	f("terraform-cloud-token", `\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,}\b`),
	f("new-relic-key", `\bNRA[KJ]-[A-Z0-9]{27}\b`),
	f("grafana-token", `\bgl(?:c|sa)_[A-Za-z0-9_=+/-]{32,}\b`),
	f("sentry-token", `\bsntry[su]_[A-Za-z0-9_=+/-]{40,}\b`),
	f("linear-api-key", `\blin_api_[A-Za-z0-9]{40}\b`),
	f("doppler-token", `\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}\b`),
	f("pulumi-token", `\bpul-[a-f0-9]{40}\b`),
	f("postman-api-key", `\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b`),
	f("telegram-bot-token", `\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b`),
	f("age-secret-key", `\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b`),
	f("jwt", `\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	f("kubernetes-sa-token", `\bk8s-aws-v1\.[A-Za-z0-9_-]{40,}\b`),
	g("url-password", `\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s/@]{3,})@`, 1),
	g("password-assignment", `(?i)\b(?:password|passwd|pwd|db_?pass)["']?\s*[:=]\s*["']?([^\s"',;]{4,})`, 1),
	g("secret-assignment", `(?i)\b(?:secret|api_?key|apikey|access_?token|auth_?token|client_?secret|private_?key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+_=.-]{16,})`, 1),
	g("bearer-token", `(?i)\b(?:authorization:\s*)?bearer\s+([A-Za-z0-9._~+/=-]{20,})`, 1),
}

// Formats lists the names of the formats found (for documentation and
// tests).
func Formats() []string {
	out := make([]string, len(formats))
	for i := range formats {
		out[i] = formats[i].Name
	}
	return out
}

// Redact replaces every secret found in s by [REDACTED:<format>].
func Redact(s string) string {
	for i := range formats {
		ft := &formats[i]
		if ft.group == 0 {
			s = ft.re.ReplaceAllString(s, "[REDACTED:"+ft.Name+"]")
			continue
		}
		s = ft.re.ReplaceAllStringFunc(s, func(m string) string {
			sub := ft.re.FindStringSubmatchIndex(m)
			if len(sub) <= 2*ft.group+1 || sub[2*ft.group] < 0 {
				return m
			}
			secret := m[sub[2*ft.group]:sub[2*ft.group+1]]
			if strings.HasPrefix(secret, "[REDACTED:") || reference(secret) {
				return m
			}
			return m[:sub[2*ft.group]] + "[REDACTED:" + ft.Name + "]" + m[sub[2*ft.group+1]:]
		})
	}
	return s
}

// reference: a value that names where a secret comes from, not the secret
// (a Terraform variable, local or data source, an interpolation).
func reference(v string) bool {
	for _, p := range []string{"var.", "local.", "data.", "module.", "each.", "count.", "path."} {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return strings.Contains(v, "${")
}

// Found reports whether s holds a secret of any format.
func Found(s string) bool { return Redact(s) != s }
