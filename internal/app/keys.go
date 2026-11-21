package app

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/iampolicy"
	"github.com/r3oof-900/clapa/internal/model"
)

// KeyPolicyNotInInput suffixes the ID of the unknown key policy of a key
// that is not in the input (graph.Undecided names the key).
const KeyPolicyNotInInput = "#key-policy-not-in-input"

// keysOutsideInput: a resource encrypted with a KMS key that no input
// describes gets that key as a node whose key policy is unknown (an
// unknown Allow and an unknown Deny), and the scan records a coverage gap.
// CAN_DECRYPT through it is then UNKNOWN, never "no edge" (DESIGN.md 7.3).
func (l *loader) keysOutsideInput() {
	var missing []string
	protects := map[string][]string{}
	for _, r := range l.b.Resources() {
		enc := r.Encryption()
		if !strings.HasPrefix(enc.Type, "aws:kms") || enc.KeyARN == "" || l.b.Has(model.NewID(model.KindKMSKey, enc.KeyARN)) {
			continue
		}
		if !slices.Contains(missing, enc.KeyARN) {
			missing = append(missing, enc.KeyARN)
		}
		protects[enc.KeyARN] = append(protects[enc.KeyARN], r.ARN())
	}
	slices.Sort(missing)
	for _, arn := range missing {
		parts := strings.SplitN(arn, ":", 6)
		region, account := "", ""
		if len(parts) == 6 {
			region, account = parts[3], parts[4]
		}
		loc := model.APILocation(arn, "not in the input")
		key := model.NewResource(&model.ResourceInput{Kind: model.KindKMSKey, ARN: arn, Account: account, Region: region, KeyRotation: model.Unknown, Source: loc})
		l.b.AddResource(key)
		l.b.AddPolicy(&model.AttachedPolicy{Target: key.ID(), Doc: l.unknownKeyPolicy(arn, &loc)})
		l.rec.Add(&coverage.Gap{
			Kind: coverage.KindUnresolved, Source: "inventory", Address: arn,
			Detail: "the KMS key that encrypts " + strings.Join(protects[arn], ", ") + " is not in the input: its key policy is unknown " +
				"(scan the key's Terraform or plan, or a snapshot of its account)",
		})
	}
}

func (l *loader) unknownKeyPolicy(arn string, loc *model.SourceLocation) *model.PolicyDocument {
	p := l.b.Placeholder("key_policy_of_" + strings.NewReplacer(":", "_", "/", "_").Replace(arn))
	allow := map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": p}, "Action": p, "Resource": p}
	deny := map[string]any{"Effect": "Deny", "Principal": map[string]any{"AWS": p}, "Action": p, "Resource": "*"}
	js, _ := json.Marshal(map[string]any{"Version": model.Version2012, "Statement": []any{allow, deny}})
	d, _ := iampolicy.Parse(js, &iampolicy.Options{ID: arn + KeyPolicyNotInInput, Kind: model.PolicyResource, Source: *loc, Placeholders: true}) // always valid
	return d
}
