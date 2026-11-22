package terraform

import (
	"strings"

	"github.com/r3oof-900/darb/internal/collect/tfraw"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/model"
)

// secretFacts is one aws_secretsmanager_secret and its policies.
type secretFacts struct {
	r        *tfraw.Resource
	policies []*model.PolicyDocument
}

// secretsData normalizes aws_secretsmanager_secret (with its policy, inline
// or aws_secretsmanager_secret_policy) and aws_ssm_parameter as data
// resources (DESIGN.md 7.3).
func (n *norm) secretsData(rs []*tfraw.Resource) {
	secrets, order := n.secretResources(rs)
	for _, r := range rs {
		switch r.Type {
		case "aws_secretsmanager_secret_policy":
			n.secretPolicy(r, secrets)
		case "aws_ssm_parameter":
			if r.Mode == "managed" {
				n.parameter(r)
			}
		}
	}
	for _, f := range order {
		r := f.r
		res := model.NewResource(&model.ResourceInput{
			Kind: model.KindSecret, ARN: n.secretARN(r), Account: n.account(r), Region: n.region(r), Tags: tags(r),
			Encryption: model.Encryption{Type: "aws:kms", KeyARN: n.keyRef(r, "kms_key_id", "alias/aws/secretsmanager")}, Source: src(r),
		})
		n.b.AddResource(res)
		for _, d := range f.policies {
			n.b.AddPolicy(&model.AttachedPolicy{Target: res.ID(), Doc: d})
		}
	}
}

// secretResources: the secrets by "root|address", in input order, each with
// its inline policy.
func (n *norm) secretResources(rs []*tfraw.Resource) (map[string]*secretFacts, []*secretFacts) {
	secrets := map[string]*secretFacts{}
	var order []*secretFacts
	for _, r := range rs {
		if r.Type != "aws_secretsmanager_secret" || r.Mode != "managed" {
			continue
		}
		f := &secretFacts{r: r}
		if v := attr(r, "policy"); v != nil && v.Kind != tfraw.KNull {
			text, ok := n.policyText(r.Root, v)
			f.policies = append(f.policies, n.parsePolicy(r, r.Address+".policy", model.PolicyResource, text, ok))
		}
		secrets[r.Root+"|"+r.Address] = f
		order = append(order, f)
	}
	return secrets, order
}

func (n *norm) secretPolicy(r *tfraw.Resource, secrets map[string]*secretFacts) {
	v := attr(r, "secret_arn")
	var f *secretFacts
	if v != nil && v.Kind == tfraw.KRef {
		f = secrets[r.Root+"|"+v.Ref.Address]
	}
	if f == nil {
		n.gap(coverage.KindUnresolved, r, "the secret is not defined in the input; this policy is not attached")
		return
	}
	text, ok := n.policyText(r.Root, attr(r, "policy"))
	f.policies = append(f.policies, n.parsePolicy(r, r.Address, model.PolicyResource, text, ok))
}

// secretARN: Secrets Manager appends six random characters to the name in
// the ARN; until Terraform knows the ARN, the suffix is unresolved, so a
// policy naming one exact secret ARN is UNKNOWN for it, never a definite no.
func (n *norm) secretARN(r *tfraw.Resource) string {
	if a, ok := r.Attrs.Str("arn"); ok && a != "" {
		return a
	}
	return "arn:" + n.opts.Partition + ":secretsmanager:" + n.region(r) + ":" + n.account(r) + ":secret:" + n.nameOf(r) + "-" +
		n.placeholder(r.Address+".arn_suffix")
}

// parameter: a SecureString (type SecureString) is encrypted with key_id,
// by default the AWS managed key aws/ssm; String and StringList are
// plaintext; a type that is not known is unknown encryption.
func (n *norm) parameter(r *tfraw.Resource) {
	typ, known := n.str(r.Root, attr(r, "type"))
	enc := model.Encryption{Type: "none"}
	switch {
	case !known || model.ContainsUnresolved(typ):
		enc = model.Encryption{}
	case typ == "SecureString":
		enc = model.Encryption{Type: "aws:kms", KeyARN: n.keyRef(r, "key_id", "alias/aws/ssm")}
	}
	n.b.AddResource(model.NewResource(&model.ResourceInput{
		Kind: model.KindSSMParameter, ARN: n.arnOf(r), Account: n.account(r), Region: n.region(r), Tags: tags(r), Encryption: enc, Source: src(r),
	}))
}

// keyRef resolves a KMS key attribute (a key ARN, a key ID, an alias) to the
// key's ARN; "" for the service's AWS managed key (managed alias, or not
// set). An alias is unresolved: aws_kms_alias targets are not followed.
func (n *norm) keyRef(r *tfraw.Resource, key, managed string) string {
	v := attr(r, key)
	if v == nil || v.Kind == tfraw.KNull {
		return ""
	}
	ref, _ := n.str(r.Root, v)
	prefix := "arn:" + n.opts.Partition + ":kms:" + n.region(r) + ":" + n.account(r) + ":"
	switch {
	case ref == "" || ref == managed || ref == prefix+managed:
		return ""
	case strings.Contains(ref, ":key/") || model.ContainsUnresolved(ref):
		return ref
	case strings.HasPrefix(ref, "alias/") || strings.Contains(ref, ":alias/"):
		return prefix + "key/" + n.placeholder(r.Address+"."+key)
	}
	return prefix + "key/" + ref
}
