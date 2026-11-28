package access

import (
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/scoring"
)

// rewriteGrant: one resource policy a principal can rewrite in its own
// account to grant itself access (item 4, DESIGN.md §7.2): the grant it
// would write, and the fixes that stop the rewrite (each Put* request's
// sides: the identity grant, and the resource policy when it grants the
// Put*, as a key policy delegating to the account does).
type rewriteGrant struct {
	doc   *model.PolicyDocument
	fixes []graph.Fix
	// decision: whether the Put* is granted: ALLOW, or UNKNOWN naming what
	// is undecided (UNKNOWN is never safe: the edge stays, and dominance
	// hides it where a direct path holds, DESIGN.md 8).
	decision eval.Decision
}

// rewriteResources: for each role and user that can rewrite, in its own
// account, a crown-jewel bucket's policy (s3:PutBucketPolicy) or the key
// policy of the key protecting one (kms:PutKeyPolicy, or kms:CreateGrant
// to itself), and does not already have that access, the synthetic
// principal "with those resource policies granting it", reached by
// CAN_ESCALATE[rewrite-resource-policy]. That edge is structural (no
// single change breaks it); the cut is on the edges out of the synthetic
// principal, priced where each Put* is granted. Every other edge is
// evaluated as usual: a bucket policy alone gives no kms:Decrypt.
func (b *builder) rewriteResources() {
	b.rewrites = map[model.ID]map[string]*rewriteGrant{}
	for _, p := range slices.Concat(b.roles, b.users) {
		if p.Kind() == model.KindAccountRoot {
			continue // no policy restricts the root
		}
		grants := b.rewritable(p)
		if len(grants) == 0 {
			continue
		}
		node, _ := b.synthetic(model.KindRewritten, p, "", b.policies[p.ID()], b.boundaries[p.ID()])
		b.rewrites[node.ID()] = grants
		b.edge(p.ID(), node.ID(), graph.CanEscalate, "rewrite-resource-policy", rewriteDecision(grants), func(e *graph.Edge) {
			e.Evidence = []string{"may rewrite the resource policy of " + joinKeys(grants)}
			e.Fixes = []graph.Fix{} // structural: the cut is on the edges out of it
		})
	}
}

// rewritable: the resources whose policy p can rewrite, in its account,
// to reach a crown jewel it does not already reach.
func (b *builder) rewritable(p *model.Principal) map[string]*rewriteGrant {
	grants := map[string]*rewriteGrant{}
	for _, j := range b.opts.Jewels {
		if j.Kind() == model.KindS3Bucket && j.Account() == p.Account() {
			if g := b.rewriteBucket(p, j); g != nil {
				grants[j.ARN()] = g
			}
		}
		if key, ok := b.resources[j.Encryption().KeyARN]; ok && key.Account() == p.Account() && grants[key.ARN()] == nil {
			if g := b.rewriteKey(p, key); g != nil {
				grants[key.ARN()] = g
			}
		}
	}
	return grants
}

func (b *builder) rewriteBucket(p *model.Principal, j *model.Resource) *rewriteGrant {
	if b.canAlready(p, "s3:GetObject", j.ARN()+"/"+model.UnresolvedPlaceholder("object-key"), j.Account(), b.policies[j.ID()], false) {
		return nil
	}
	return b.rewriteVia(p, j.ARN(), j.Account(), b.policies[j.ID()], false, "bucket policy",
		resourceGrant(p, "s3:GetObject", j.ARN()+"/*"), putRequest{action: "s3:PutBucketPolicy"})
}

func (b *builder) rewriteKey(p *model.Principal, key *model.Resource) *rewriteGrant {
	if b.canAlready(p, "kms:Decrypt", key.ARN(), key.Account(), b.policies[key.ID()], true) {
		return nil
	}
	// A grant to itself: the grantee is the caller, for Decrypt, from a
	// direct call (KMS Developer Guide › kms:GranteePrincipal,
	// kms:GrantOperations, kms:GrantIsForAWSResource).
	grant := putRequest{action: "kms:CreateGrant", present: map[string][]string{
		"kms:GranteePrincipal": {p.Identity()}, "kms:GrantOperations": {"Decrypt"}, "kms:GrantIsForAWSResource": {"false"},
	}}
	return b.rewriteVia(p, key.ARN(), key.Account(), b.policies[key.ID()], true, "key policy",
		resourceGrant(p, "kms:Decrypt", "*"), putRequest{action: "kms:PutKeyPolicy"}, grant)
}

type putRequest struct {
	action  string
	present map[string][]string
}

// canAlready: the principal already has the access (ALLOW): rewriting adds
// nothing for it.
func (b *builder) canAlready(p *model.Principal, action, resource, account string, res []*model.PolicyDocument, required bool) bool {
	req := &eval.Request{Principal: b.session(p), Action: action, Resource: resource, ResourceAccount: account, Context: b.context(p, action, resource, nil)}
	return eval.Evaluate(req, b.identitySet(p, res, required)).Verdict == eval.Allow
}

// rewriteVia: the rewrite through any of puts (ALLOW, or UNKNOWN: never
// dropped); its fixes are every side of every granting put (all of them
// must go for the rewrite to stop).
func (b *builder) rewriteVia(p *model.Principal, resource, account string, res []*model.PolicyDocument, required bool, label string,
	doc *model.PolicyDocument, puts ...putRequest,
) *rewriteGrant {
	var fixes []graph.Fix
	best := &eval.Decision{Verdict: eval.ImplicitDeny}
	set := b.identitySet(p, res, required)
	for _, put := range puts {
		req := &eval.Request{
			Principal: b.session(p), Action: put.action, Resource: resource, ResourceAccount: account,
			Context: b.context(p, put.action, resource, put.present),
		}
		d := eval.Evaluate(req, set)
		if !grants(d.Verdict) {
			continue
		}
		for i := range d.Unresolved {
			d.Unresolved[i].Reason = "for " + put.action + " on " + resource + ": " + d.Unresolved[i].Reason
		}
		if better(&d, best) {
			best = &d
		}
		t := &grantTarget{action: put.action, resource: resource, principal: p.Identity()}
		fixes = mergeFixes(fixes, b.policyFixes(graph.CanEscalate, req, set, p, resource, label, t, nil))
	}
	if !grants(best.Verdict) {
		return nil
	}
	return &rewriteGrant{doc: doc, fixes: nonNil(fixes), decision: *best}
}

// rewriteDecision: the rewrite edge holds when any one rewrite does: the
// best of them, with what each UNKNOWN leaves undecided.
func rewriteDecision(grants map[string]*rewriteGrant) *eval.Decision {
	best := &eval.Decision{Verdict: eval.ImplicitDeny}
	var unresolved []eval.Unresolved
	for _, k := range sortedKeys(grants) {
		d := grants[k].decision
		unresolved = append(unresolved, d.Unresolved...)
		if better(&d, best) {
			best = &d
		}
	}
	out := *best
	if out.Verdict == eval.Unknown {
		out.Unresolved = unresolved
	}
	return &out
}

// mergeFixes: one fix per side, every grant of either.
func mergeFixes(into, add []graph.Fix) []graph.Fix {
	if into == nil {
		return slices.Clone(add)
	}
	for i := range add {
		k := slices.IndexFunc(into, func(f graph.Fix) bool { return f.Side == add[i].Side })
		if k < 0 {
			into = append(into, add[i])
			continue
		}
		mergeSide(&into[k], &add[i])
		if into[k].Kind == graph.FixNarrow || into[k].Kind == graph.FixRevoke {
			into[k].Cost = scoring.FixCost(graph.CanEscalate, "", into[k].Side, into[k].Kind)
		}
	}
	sortFixes(into)
	return into
}

// resourceGrant: the statement the principal would write for itself.
func resourceGrant(p *model.Principal, action, resource string) *model.PolicyDocument {
	d, _ := model.NewPolicyDocument(&model.PolicyInput{ // a fixed, valid document
		ID: "darb:rewritten:" + action + ":" + p.Identity(), Kind: model.PolicyResource, Version: model.Version2012,
		Statements: []*model.StatementInput{{
			Effect: model.EffectAllow, Action: []string{action}, Resource: []string{resource},
			Principal: model.NewPrincipalSpec(false, []model.PrincipalRef{{Type: model.PrincipalAWS, Value: p.Identity()}}),
		}},
	})
	return d
}

// resourceDocs: a resource's policies, with the grant a rewritten
// principal writes for itself.
func (b *builder) resourceDocs(who *model.Principal, id model.ID, arn string) []*model.PolicyDocument {
	docs := b.policies[id]
	if who != nil {
		if g, ok := b.rewrites[who.ID()][arn]; ok {
			return append(slices.Clone(docs), g.doc)
		}
	}
	return docs
}

// rewriteFixes: the fixes of an edge a rewritten principal has through a
// resource policy it rewrote.
func (b *builder) rewriteFixes(who *model.Principal, arn string) ([]graph.Fix, bool) {
	if who == nil {
		return nil, false
	}
	g, ok := b.rewrites[who.ID()][arn]
	if !ok {
		return nil, false
	}
	return slices.Clone(g.fixes), true
}

func sortedKeys(m map[string]*rewriteGrant) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func joinKeys(m map[string]*rewriteGrant) string {
	return strings.Join(sortedKeys(m), ", ")
}
