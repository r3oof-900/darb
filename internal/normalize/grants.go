package normalize

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/model"
)

// Grant is one KMS grant, as ListGrants or an aws_kms_grant gives it
// (KMS API Reference › GrantListEntry).
type Grant struct {
	ID         string   // GrantId, or the Terraform address
	Grantee    string   // GranteePrincipal: an ARN, or a service principal
	Operations []string // e.g. Decrypt, CreateGrant
	// Equals and Subset are the grant's constraints (GrantConstraints):
	// EncryptionContextEquals and EncryptionContextSubset, never both.
	Equals, Subset map[string]string
}

// GrantPolicy renders a grant as the resource policy statement it acts as
// on its key (decided after v0.1.0-rc.1, DESIGN.md §6, KMS grants): an
// Allow of its operations to its grantee. A grant "can allow access to a
// KMS key, but not deny access" (KMS Developer Guide › Grants in AWS KMS),
// so Denies elsewhere still apply. Its constraints become exact
// conditions (KMS API Reference › GrantConstraints):
//
//   - EncryptionContextEquals, "an exact, case-sensitive match": every
//     pair, as StringEquals on kms:EncryptionContext:<key>, and no other
//     key, as ForAllValues:StringEquals on kms:EncryptionContextKeys;
//   - EncryptionContextSubset, the request "can also have additional
//     encryption context pairs": every pair only.
//
// Condition keys are case-insensitive and StringEquals compares values
// with case, as the constraint does ("the key in each key-value pair is not
// case sensitive, but the value is case sensitive").
func GrantPolicy(g *Grant) string {
	principal := map[string]string{"AWS": g.Grantee}
	if !strings.Contains(g.Grantee, ":") {
		principal = map[string]string{"Service": g.Grantee}
	}
	actions := make([]string, 0, len(g.Operations))
	for _, op := range g.Operations {
		actions = append(actions, "kms:"+op)
	}
	slices.Sort(actions)
	st := map[string]any{"Sid": "grant", "Effect": "Allow", "Principal": principal, "Action": actions, "Resource": "*"}
	cond := map[string]any{}
	pairs := g.Subset
	if len(g.Equals) > 0 {
		pairs = g.Equals
		keys := make([]string, 0, len(g.Equals))
		for k := range g.Equals {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		cond["ForAllValues:StringEquals"] = map[string]any{"kms:EncryptionContextKeys": keys}
	}
	if len(pairs) > 0 {
		eq := map[string]string{}
		for k, v := range pairs {
			eq["kms:EncryptionContext:"+k] = v
		}
		cond["StringEquals"] = eq
	}
	if len(cond) > 0 {
		st["Condition"] = cond
	}
	data, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{st}}) // maps of strings: cannot fail
	return string(data)
}

// GrantDocID is the policy ID of a grant on a key.
func GrantDocID(keyARN, id string) string { return keyARN + model.GrantDocMarker + id }
