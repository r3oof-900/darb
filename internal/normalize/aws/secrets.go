package aws

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/r3oof-900/clapa/internal/model"
)

// secrets: each Secrets Manager secret is a data resource encrypted with
// its KMS key ("" for the AWS managed key aws/secretsmanager), with its
// resource policy.
func (n *norm) secrets() {
	for _, s := range n.acct.Secrets {
		loc := apiLoc(s.ARN, "secretsmanager:ListSecrets")
		res := model.NewResource(&model.ResourceInput{
			Kind: model.KindSecret, ARN: s.ARN, Account: n.acct.ID, Region: s.Region, Tags: tagMap(s.Tags),
			Encryption: model.Encryption{Type: "aws:kms", KeyARN: n.keyARN(s.Region, s.KMSKeyID, "alias/aws/secretsmanager")}, Source: loc,
		})
		n.b.AddResource(res)
		ploc := apiLoc(s.ARN, "secretsmanager:GetResourcePolicy")
		switch {
		case s.PolicyFailed:
			n.b.AddPolicy(&model.AttachedPolicy{Target: res.ID(), Doc: n.unknownDoc(s.ARN+"#resource-policy", model.PolicyResource, &ploc)})
		case s.Policy != "":
			raw, _ := json.Marshal(s.Policy)
			n.b.AddPolicy(&model.AttachedPolicy{Target: res.ID(), Doc: n.parse(raw, s.ARN+"#resource-policy", model.PolicyResource, &ploc)})
		}
	}
}

// parameters: each Systems Manager parameter is a data resource; a
// SecureString is encrypted with its KMS key ("" for the AWS managed key
// aws/ssm), String and StringList are plaintext. Resource policies (shared
// advanced parameters) are attached.
func (n *norm) parameters() {
	for _, p := range n.acct.Params {
		loc := apiLoc(p.ARN, "ssm:DescribeParameters")
		enc := model.Encryption{Type: "none"}
		if p.Type == "SecureString" {
			enc = model.Encryption{Type: "aws:kms", KeyARN: n.keyARN(p.Region, p.KeyID, "alias/aws/ssm")}
		}
		res := model.NewResource(&model.ResourceInput{
			Kind: model.KindSSMParameter, ARN: p.ARN, Account: n.acct.ID, Region: p.Region, Tags: tagMap(p.Tags), Encryption: enc, Source: loc,
		})
		n.b.AddResource(res)
		ploc := apiLoc(p.ARN, "ssm:GetResourcePolicies")
		if p.PolicyFailed {
			n.b.AddPolicy(&model.AttachedPolicy{Target: res.ID(), Doc: n.unknownDoc(p.ARN+"#resource-policy", model.PolicyResource, &ploc)})
		}
		for i, text := range p.Policies {
			raw, _ := json.Marshal(text)
			n.b.AddPolicy(&model.AttachedPolicy{Target: res.ID(), Doc: n.parse(raw, p.ARN+"#resource-policy/"+strconv.Itoa(i), model.PolicyResource, &ploc)})
		}
	}
}

// keyARN resolves a KMS key reference (key ARN, key ID, alias name or alias
// ARN) to the key's ARN in the account and region; "" when it names the
// service's AWS managed key (managed, e.g. "alias/aws/ssm", or no key). An
// alias the snapshot does not resolve is an unresolved placeholder: the
// decrypt is UNKNOWN, never assumed.
func (n *norm) keyARN(region, ref, managed string) string {
	prefix := "arn:" + n.acct.Partition + ":kms:" + region + ":" + n.acct.ID + ":"
	alias := ref
	switch {
	case ref == "", ref == managed, ref == prefix+managed:
		return ""
	case strings.Contains(ref, ":key/"):
		return ref
	case strings.HasPrefix(ref, prefix+"alias/"):
		alias = strings.TrimPrefix(ref, prefix)
	case !strings.HasPrefix(ref, "alias/"):
		return prefix + "key/" + ref // a key ID
	}
	for _, a := range n.acct.Aliases {
		if a.Region == region && a.AliasName == alias && a.TargetKeyID != "" {
			return prefix + "key/" + a.TargetKeyID
		}
	}
	return prefix + "key/" + n.b.Placeholder("kms_alias_"+strings.NewReplacer("/", "_", ":", "_").Replace(alias))
}
