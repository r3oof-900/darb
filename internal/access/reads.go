package access

import (
	"slices"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/eval/match"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
)

// nodeRoles adds NODE_ROLE: a pod reaches its node's instance role through
// IMDS when hostNetwork is set (unless IMDS is disabled), when IMDSv1 is
// allowed, or when the IMDSv2 hop limit lets the token response reach a
// container (>= 2).
func (b *builder) nodeRoles() {
	for _, w := range b.inv.Workloads {
		for _, ng := range b.inv.NodeGroups {
			role, ok := b.byARN[ng.RoleARN]
			if ng.Cluster != w.Cluster() || !ok {
				continue
			}
			state := imdsReachable(w.HostNetwork(), ng)
			if state == model.False {
				continue
			}
			verdict, conf := eval.Allow, graph.High
			if state == model.Unknown {
				verdict, conf = eval.Unknown, graph.Low
			}
			b.edge(w.ID(), role.ID(), graph.NodeRole, "", &eval.Decision{Verdict: verdict}, func(e *graph.Edge) {
				e.Confidence = conf
				e.Precondition = &graph.Precondition{Reason: "IMDS reachable from the pod (node group " + ng.Name + ")", State: state}
				e.Evidence = []string{"node group " + ng.Source.String()}
				e.Fixes = nodeRoleFixes(w, ng)
			})
		}
	}
}

func imdsReachable(hostNetwork bool, ng *model.NodeGroup) model.Tri {
	switch {
	case ng.HTTPEndpoint == "disabled":
		return model.False
	case ng.HTTPEndpoint == "" || ng.HTTPTokens == "":
		if hostNetwork && ng.HTTPEndpoint != "" {
			return model.True
		}
		return model.Unknown
	case hostNetwork, ng.HTTPTokens == "optional", ng.HopLimit >= 2:
		return model.True
	case ng.HopLimit == 0:
		return model.Unknown
	}
	return model.False
}

// reads adds CAN_READ, CAN_DECRYPT[for J] and the derived
// CAN_READ_PLAINTEXT from every role (and the anonymous principal) to every
// crown-jewel bucket (DESIGN.md §7.3).
func (b *builder) reads() {
	protected := map[string]bool{}
	for _, j := range b.opts.Jewels {
		if j.Kind() != model.KindS3Bucket {
			continue
		}
		if k := j.Encryption().KeyARN; k != "" {
			protected[k] = true
		}
		b.g.Node(j.ID(), j.Kind(), j.ARN())
		for _, role := range append(slices.Clone(b.roles), b.order...) {
			b.read(role, j)
		}
		b.read(nil, j)
	}
	for _, j := range b.opts.Jewels {
		if j.Kind() == model.KindKMSKey && !protected[j.ARN()] {
			b.notes = append(b.notes, Note{
				Kind: "protected-data-outside-input", Subject: j.ARN(),
				Detail: "the key is a crown jewel but protects no resource in the input; the data it protects is outside the input and is not analysed",
			})
		}
	}
}

// read evaluates one principal (nil: anonymous) against one bucket.
func (b *builder) read(role *model.Principal, j *model.Resource) {
	from := AnonymousID()
	principal := match.RequestPrincipal{Kind: match.KindAnonymous}
	var set *eval.PolicySet
	if role == nil {
		b.g.Node(from, model.KindAnonymous, Anonymous)
		set = &eval.PolicySet{Resource: b.policies[j.ID()]}
	} else {
		from, principal = role.ID(), b.session(role)
		set = b.identitySet(role, b.policies[j.ID()], false)
	}
	object := j.ARN() + "/" + model.UnresolvedPlaceholder("object-key")
	req := &eval.Request{Principal: principal, Action: "s3:GetObject", Resource: object, ResourceAccount: j.Account(), Context: b.context(role, nil)}
	read := eval.Evaluate(req, set)
	if role == nil {
		read.Verdict = publicAccess(read.Verdict, j.S3().RestrictPublicBuckets)
	}
	if !grants(read.Verdict) {
		return
	}
	rewrite := b.canDo(role, "s3:PutBucketPolicy", j.ARN(), j.Account(), b.policies[j.ID()], false)
	readEdge := b.edge(from, j.ID(), graph.CanRead, sub(role), &read, func(e *graph.Edge) {
		e.Fixes = nonNil(b.policyFixes(graph.CanRead, req, set, role, j.ARN(), "bucket policy",
			&grantTarget{action: "s3:GetObject", prefix: j.ARN() + "/", principal: identityOf(role)}, rewrite))
	})
	under := []graph.EdgeID{readEdge}
	verdict := read.Verdict
	enc := j.Encryption()
	switch enc.Type {
	case "AES256", "none":
	case "aws:kms", "aws:kms:dsse":
		dec, edge, ok := b.decrypt(role, principal, j)
		if !ok {
			return
		}
		verdict = both(verdict, dec)
		under = append(under, edge)
	default:
		verdict = both(verdict, eval.Unknown) // encryption not in the input
	}
	if !grants(verdict) {
		return
	}
	b.edge(from, j.ID(), graph.CanReadPlaintext, sub(role), &eval.Decision{Verdict: verdict}, func(e *graph.Edge) {
		e.Under = under
		e.Evidence = nil
		if slices.Contains(j.Defaulted(), model.DefaultS3Encryption) {
			e.Defaults = []string{model.DefaultS3Encryption}
		}
	})
}

func sub(role *model.Principal) string {
	if role == nil {
		return "public"
	}
	return ""
}

// publicAccess: RestrictPublicBuckets blocks access granted to public
// principals (S3 User Guide › Blocking public access); unknown leaves it unknown.
func publicAccess(v eval.Verdict, restrict model.Tri) eval.Verdict {
	switch {
	case !grants(v) || restrict == model.False:
		return v
	case restrict == model.True:
		return eval.ImplicitDeny
	}
	return both(v, eval.Unknown)
}

// decrypt evaluates kms:Decrypt by S3 for this bucket. The encryption context
// aws:s3:arn is the bucket ARN with an S3 Bucket Key and the object ARN
// without (S3 User Guide › "Encryption context"); when the Bucket Key setting
// is unknown, both are tried and the result is definite only if they agree.
func (b *builder) decrypt(role *model.Principal, principal match.RequestPrincipal, j *model.Resource) (eval.Verdict, graph.EdgeID, bool) {
	enc := j.Encryption()
	if enc.KeyARN == "" {
		return b.awsManagedKey(role, j)
	}
	key, ok := b.resources[enc.KeyARN]
	if !ok || role == nil {
		return eval.ImplicitDeny, 0, false // anonymous cannot use a KMS key; a key outside the input is not analysed
	}
	object := j.ARN() + "/" + model.UnresolvedPlaceholder("object-key")
	contexts := map[model.Tri][]string{model.True: {j.ARN()}, model.False: {object}}[enc.BucketKey]
	if contexts == nil {
		contexts = []string{j.ARN(), object}
	}
	var result *eval.Decision
	var req *eval.Request
	set := b.identitySet(role, b.policies[key.ID()], true)
	for _, c := range contexts {
		req = &eval.Request{
			Principal: principal, Action: "kms:Decrypt", Resource: key.ARN(), ResourceAccount: key.Account(),
			Context: b.context(role, map[string][]string{"kms:EncryptionContext:aws:s3:arn": {c}, "kms:EncryptionContextKeys": {"aws:s3:arn"}}),
		}
		d := eval.Evaluate(req, set)
		if result == nil {
			result = &d
		} else if result.Verdict != d.Verdict {
			result.Verdict = both(either(result.Verdict, d.Verdict), eval.Unknown)
		}
	}
	if !grants(result.Verdict) {
		return result.Verdict, 0, false
	}
	b.g.Node(key.ID(), key.Kind(), key.ARN())
	rewrite := b.canDo(role, "kms:PutKeyPolicy", key.ARN(), key.Account(), b.policies[key.ID()], true) ||
		b.canDo(role, "kms:CreateGrant", key.ARN(), key.Account(), b.policies[key.ID()], true)
	e := b.edge(role.ID(), key.ID(), graph.CanDecrypt, "", result, func(e *graph.Edge) {
		e.For = b.node(j.ID())
		e.Fixes = nonNil(b.policyFixes(graph.CanDecrypt, req, set, role, key.ARN(), "key policy",
			&grantTarget{action: "kms:Decrypt", principal: identityOf(role), context: j.ARN()}, rewrite))
	})
	return result.Verdict, e, true
}

// awsManagedKey: SSE-KMS with the AWS managed key aws/s3, whose key policy
// lets principals of the account use it through S3; principals of another
// account cannot.
func (b *builder) awsManagedKey(role *model.Principal, j *model.Resource) (eval.Verdict, graph.EdgeID, bool) {
	if role == nil || model.ContainsUnresolved(role.Account()) || model.ContainsUnresolved(j.Account()) || j.Account() == "" {
		if role != nil {
			return eval.Unknown, b.readOnlyKeyEdge(role, j, eval.Unknown), true
		}
		return eval.ImplicitDeny, 0, false
	}
	if role.Account() != j.Account() {
		return eval.ImplicitDeny, 0, false
	}
	return eval.Allow, b.readOnlyKeyEdge(role, j, eval.Allow), true
}

func (b *builder) readOnlyKeyEdge(role *model.Principal, j *model.Resource, v eval.Verdict) graph.EdgeID {
	id := model.NewID(model.KindKMSKey, "aws/s3@"+j.Account())
	b.g.Node(id, model.KindKMSKey, "alias/aws/s3 ("+j.Account()+")")
	return b.edge(role.ID(), id, graph.CanDecrypt, "aws-managed", &eval.Decision{Verdict: v}, func(e *graph.Edge) { e.For = b.node(j.ID()) })
}

// nonNil marks "no single change breaks it" (an empty list) apart from
// "not computed" (nil, which takes the default fixes).
// identityOf: the principal's ARN; "" for the anonymous caller (nil), which
// only a Principal "*" grants: never explicit.
func identityOf(p *model.Principal) string {
	if p == nil {
		return ""
	}
	return p.Identity()
}

func nonNil(fs []graph.Fix) []graph.Fix {
	if fs == nil {
		return []graph.Fix{}
	}
	return fs
}
