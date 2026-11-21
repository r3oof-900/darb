package access

import (
	"strings"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
)

// Secrets Manager secrets and SSM parameters (DESIGN.md 7.3): CAN_READ is
// the API that returns the value; with a KMS key, the plaintext also needs
// CAN_DECRYPT[for J] on the key, evaluated with the encryption context the
// service sends and kms:ViaService; an AWS managed key lets principals of
// the account use it through the service (documented default).

// secretRead describes how one kind of secret is read and decrypted.
type secretRead struct {
	actions  []string                         // any of them returns the value
	targets  func(j *model.Resource) []string // the resource ARNs the actions are authorized on
	contexts func(j *model.Resource) map[string][]string
	service  string // kms:ViaService prefix: "secretsmanager", "ssm"
	rewrite  string // the action that rewrites the resource policy
	managed  string // the AWS managed key's alias
	label    string // "secret resource policy"
	defaults string // the documented default of the AWS managed key
}

func secretsManagerRead() *secretRead {
	return &secretRead{
		actions: []string{"secretsmanager:GetSecretValue"},
		targets: func(j *model.Resource) []string { return []string{j.ARN()} },
		// Secrets Manager encrypts with the context SecretARN and SecretVersionId
		// (Secrets Manager User Guide, "Secret encryption and decryption");
		// the version is not known statically, so its key is unknown.
		contexts: func(j *model.Resource) map[string][]string {
			return map[string][]string{
				"kms:EncryptionContext:SecretARN": {j.ARN()}, "kms:EncryptionContextKeys": {"SecretARN", "SecretVersionId"},
			}
		},
		service: "secretsmanager", rewrite: "secretsmanager:PutResourcePolicy", managed: "alias/aws/secretsmanager", label: "secret resource policy",
		defaults: model.DefaultSecretsManagedKey,
	}
}

func parameterRead() *secretRead {
	return &secretRead{
		// Each of these returns the value; GetParametersByPath is authorized
		// on the path, so every ancestor path of the parameter counts
		// (Systems Manager User Guide, "Restricting access to Parameter Store
		// parameters using IAM policies").
		actions: []string{"ssm:GetParameter", "ssm:GetParameters", "ssm:GetParameterHistory", "ssm:GetParametersByPath"},
		targets: parameterPaths,
		// Parameter Store encrypts with the context PARAMETER_ARN (Systems
		// Manager User Guide, "AWS KMS encryption for SecureString parameters").
		contexts: func(j *model.Resource) map[string][]string {
			return map[string][]string{
				"kms:EncryptionContext:PARAMETER_ARN": {j.ARN()}, "kms:EncryptionContextKeys": {"PARAMETER_ARN"},
			}
		},
		service: "ssm", rewrite: "ssm:PutResourcePolicy", managed: "alias/aws/ssm", label: "parameter resource policy",
		defaults: model.DefaultSSMManagedKey,
	}
}

// parameterPaths: the parameter's ARN, then each ancestor path
// ("arn:...:parameter/prod/db/password" -> ".../prod/db", ".../prod", ".../").
func parameterPaths(j *model.Resource) []string {
	arn := j.ARN()
	out := []string{arn}
	head, name, ok := strings.Cut(arn, ":parameter/")
	if !ok {
		return out
	}
	parts := strings.Split(name, "/")
	for i := len(parts) - 1; i >= 1; i-- {
		out = append(out, head+":parameter/"+strings.Join(parts[:i], "/"))
	}
	return append(out, head+":parameter/")
}

// readSecret adds CAN_READ, CAN_DECRYPT[for J] and CAN_READ_PLAINTEXT from
// role to the secret or parameter j.
func (b *builder) readSecret(role *model.Principal, j *model.Resource, how *secretRead) {
	principal := b.session(role)
	set := b.identitySet(role, b.policies[j.ID()], false)
	var best *eval.Request
	read := eval.Decision{Verdict: eval.ImplicitDeny}
	for _, target := range how.targets(j) {
		for _, action := range how.actions {
			if action == "ssm:GetParametersByPath" && target == j.ARN() || action != "ssm:GetParametersByPath" && target != j.ARN() {
				continue // GetParametersByPath names the path; the others the parameter
			}
			req := &eval.Request{Principal: principal, Action: action, Resource: target, ResourceAccount: j.Account(), Context: b.context(role, nil)}
			if d := eval.Evaluate(req, set); d.Verdict.Grants() > read.Verdict.Grants() {
				read, best = d, req
			}
		}
	}
	if !grants(read.Verdict) {
		return
	}
	rewrite := b.rewriter(role, j.ARN(), j.Account(), b.policies[j.ID()], false, how.rewrite)
	readEdge := b.edge(role.ID(), j.ID(), graph.CanRead, "", &read, func(e *graph.Edge) {
		e.Fixes = nonNil(b.policyFixes(graph.CanRead, best, set, role, j.ARN(), how.label,
			&grantTarget{action: best.Action, resource: best.Resource, principal: identityOf(role)}, rewrite))
	})
	verdict, under := read.Verdict, []graph.EdgeID{readEdge}
	if enc := j.Encryption(); enc.Type == "aws:kms" {
		dec, edge, ok := b.decryptSecret(role, j, how)
		if !ok {
			return
		}
		verdict, under = both(verdict, dec), append(under, edge)
	}
	if !grants(verdict) {
		return
	}
	b.edge(role.ID(), j.ID(), graph.CanReadPlaintext, "", &eval.Decision{Verdict: verdict}, func(e *graph.Edge) {
		e.Under = under
		e.Evidence = nil
	})
}

// decryptSecret evaluates kms:Decrypt by the service for j.
func (b *builder) decryptSecret(role *model.Principal, j *model.Resource, how *secretRead) (eval.Verdict, graph.EdgeID, bool) {
	keyARN := j.Encryption().KeyARN
	if keyARN == "" {
		return b.managedSecretKey(role, j, how)
	}
	key, ok := b.resources[keyARN]
	if !ok {
		// The key is not in the input (or its alias was not resolved): what
		// its policy allows is unknown, never denied.
		id := model.NewID(model.KindKMSKey, keyARN)
		b.g.Node(id, model.KindKMSKey, keyARN)
		e := b.edge(role.ID(), id, graph.CanDecrypt, "", &eval.Decision{Verdict: eval.Unknown}, func(e *graph.Edge) {
			e.For = b.node(j.ID())
			e.Evidence = []string{"the key " + keyARN + " is not in the input: its key policy is unknown"}
		})
		return eval.Unknown, e, true
	}
	present := how.contexts(j)
	present["kms:ViaService"] = []string{how.service + "." + j.Region() + ".amazonaws.com"}
	present["kms:CallerAccount"] = []string{role.Account()}
	req := &eval.Request{Principal: b.session(role), Action: "kms:Decrypt", Resource: key.ARN(), ResourceAccount: key.Account(), Context: b.context(role, present)}
	set := b.identitySet(role, b.policies[key.ID()], true)
	d := eval.Evaluate(req, set)
	if !grants(d.Verdict) {
		return d.Verdict, 0, false
	}
	b.g.Node(key.ID(), key.Kind(), key.ARN())
	rewrite := b.rewriter(role, key.ARN(), key.Account(), b.policies[key.ID()], true, "kms:PutKeyPolicy", "kms:CreateGrant")
	e := b.edge(role.ID(), key.ID(), graph.CanDecrypt, "", &d, func(e *graph.Edge) {
		e.For = b.node(j.ID())
		e.Fixes = nonNil(b.policyFixes(graph.CanDecrypt, req, set, role, key.ARN(), "key policy",
			&grantTarget{action: "kms:Decrypt", principal: identityOf(role), context: j.ARN()}, rewrite))
	})
	return d.Verdict, e, true
}

// managedSecretKey: the AWS managed key of the service lets principals of
// the account use it through the service, and only them: AWS managed keys
// cannot be used across accounts (documented defaults).
func (b *builder) managedSecretKey(role *model.Principal, j *model.Resource, how *secretRead) (eval.Verdict, graph.EdgeID, bool) {
	v := eval.Allow
	switch {
	case model.ContainsUnresolved(role.Account()) || model.ContainsUnresolved(j.Account()) || j.Account() == "":
		v = eval.Unknown
	case role.Account() != j.Account():
		return eval.ImplicitDeny, 0, false
	}
	id := model.NewID(model.KindKMSKey, strings.TrimPrefix(how.managed, "alias/")+"@"+j.Account()+"/"+j.Region())
	b.g.Node(id, model.KindKMSKey, how.managed+" ("+j.Account()+", "+j.Region()+")")
	e := b.edge(role.ID(), id, graph.CanDecrypt, "aws-managed", &eval.Decision{Verdict: v}, func(e *graph.Edge) {
		e.For = b.node(j.ID())
		e.Defaults = []string{how.defaults}
	})
	return v, e, true
}
