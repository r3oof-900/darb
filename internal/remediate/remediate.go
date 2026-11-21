package remediate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
)

// Remediation (DESIGN.md §9). A finding's plan has one change per cut edge,
// on the side the cut chose (its cheapest fix, SCORING.md §4). A change is a
// list of edits to the canonical model; the verifier applies them in memory
// and the patcher renders the same edits to the input files, so each level
// checks the other. An UNKNOWN finding gets no change: its plan says what is
// missing to decide it. A change that cannot be placed exactly is a TODO
// with the reason, never a guess: every value in an edit is a name from the
// input.

// Op is the kind of one edit.
type Op string

// Edits.
const (
	// OpAddStatement appends Statement to the policy document Policy.
	OpAddStatement Op = "add-statement"
	// OpRemoveValues removes Values from the Element ("Resource" or
	// "Principal") of statement Index of Policy; the statement goes when
	// none remain.
	OpRemoveValues Op = "remove-values"
	// OpSetValues replaces the Element of statement Index of Policy with
	// Values (a root-cause fix: the broad grant made exact).
	OpSetValues Op = "set-values"
	// OpRemoveStatement removes statement Index of Policy.
	OpRemoveStatement Op = "remove-statement"
	// OpNodeMetadata sets a node group's instance metadata options: Tokens
	// and HopLimit, or Endpoint.
	OpNodeMetadata Op = "node-metadata"
	// OpRemoveHostNetwork removes hostNetwork from Workload's pod spec.
	OpRemoveHostNetwork Op = "remove-host-network"
	// OpRemoveExposure removes Exposure: its Service becomes ClusterIP.
	OpRemoveExposure Op = "remove-exposure"
	// OpRestrictPublic turns on restrict_public_buckets for Bucket.
	OpRestrictPublic Op = "restrict-public-buckets"
	// OpDisableTokenMount sets automountServiceAccountToken: false in
	// Workload's pod spec.
	OpDisableTokenMount Op = "disable-token-mount"
)

// Edit is one change to the model.
type Edit struct {
	Op        Op
	Policy    string // policy document ID
	Statement *model.StatementInput
	Index     int
	Element   string
	Values    []string
	NodeGroup *model.NodeGroup
	Tokens    string
	HopLimit  int
	Endpoint  string
	Workload  *model.Workload
	Exposure  *model.NetworkExposure
	Bucket    *model.Resource
}

// Change breaks one edge.
type Change struct {
	Edge  string // the edge, as the graph describes it
	Side  string
	Kind  string // graph.FixNarrow or graph.FixRevoke
	Cost  int64
	Edits []Edit
	// TODO, when set: no edit is generated; why, and what to change by hand.
	TODO string
	// Why: what the change does, in one sentence.
	Why string
}

// Plan is the remediation of one finding.
type Plan struct {
	Fingerprint string
	// Missing: an UNKNOWN finding is not patched; these would decide it.
	Missing []string
	// NoFix: no finite cut within the constraints (intended access,
	// uncuttable edges).
	NoFix bool
	// Strategy: StrategyRootCause or StrategyMitigation.
	Strategy string
	Changes  []Change
	// Suggestion: a root-cause fix the input cannot verify (no declared
	// intended access uses the grant): what to narrow, by hand; no edits.
	Suggestion string
}

// Input is what the generator reads.
type Input struct {
	Inventory *model.Inventory
	Graph     *graph.Graph
	// Intended: the edges on the paths that realise declared intended
	// access (with the edges derived ones stand for).
	Intended map[graph.EdgeID]bool
}

// ForEdge generates the change that breaks one edge on one of its sides.
func ForEdge(in *Input, id graph.EdgeID, fx *graph.Fix) Change {
	g := in.Graph
	e := g.Edge(id)
	c := Change{Edge: g.Describe(id), Side: fx.Side, Kind: fx.Kind, Cost: fx.Cost}
	x := &context{in: in, g: g, e: e, fix: fx, change: &c, sid: sid(c.Edge)}
	switch e.Kind {
	case graph.CanRead:
		x.read()
	case graph.CanDecrypt:
		x.decrypt()
	case graph.Assumes:
		x.assume()
	case graph.NodeRole:
		x.nodeRole()
	case graph.ExposedTo:
		x.exposure()
	case graph.CanEscalate:
		if e.Sub == "k8s-token" && fx.Side == graph.SideWorkload {
			x.tokenMount()
			break
		}
		c.TODO = fmt.Sprintf("no generator for %s fixes yet (%s side: %s); change it by hand", e.Kind, fx.Side, fx.Policy)
	case graph.RunsAs, graph.MapsTo, graph.CanReadPlaintext, graph.Protects:
		c.TODO = fmt.Sprintf("no generator for %s fixes yet (%s side: %s); change it by hand", e.Kind, fx.Side, fx.Policy)
	}
	return c
}

// sid is the Sid of an added statement: stable for the edge.
func sid(edge string) string {
	sum := sha256.Sum256([]byte(edge))
	return "ClapaCut" + hex.EncodeToString(sum[:4])
}

type context struct {
	in     *Input
	g      *graph.Graph
	e      *graph.Edge
	fix    *graph.Fix
	change *Change
	sid    string
}

func (x *context) from() string { return x.g.Node(x.e.From).Identity }
func (x *context) to() string   { return x.g.Node(x.e.To).Identity }

func (x *context) todo(format string, args ...any) { x.change.TODO = fmt.Sprintf(format, args...) }

// read: s3:GetObject on the bucket's objects.
func (x *context) read() {
	bucket, role := x.to(), x.from()
	objects := bucket + "/*"
	t := &target{action: "s3:GetObject", objects: bucket + "/", principal: role}
	switch {
	case x.fix.Side == graph.SideResource && role == "anonymous":
		// A public grant: Block Public Access makes public bucket policies
		// ineffective ("restrict_public_buckets", S3 User Guide › Blocking
		// public access).
		b := x.resource(bucket)
		if b == nil {
			x.todo("bucket %s is not in the input", bucket)
			return
		}
		x.change.Edits = []Edit{{Op: OpRestrictPublic, Bucket: b}}
		x.change.Why = "turn on restrict_public_buckets for " + bucket + ": the public bucket policy no longer applies"
	case x.fix.Side == graph.SideIdentity:
		x.policySide(t, &model.StatementInput{Action: []string{"s3:GetObject"}, Resource: []string{objects}},
			"deny s3:GetObject on "+objects+" to "+role)
	default:
		x.policySide(t, &model.StatementInput{Principal: awsPrincipal(role), Action: []string{"s3:GetObject"}, Resource: []string{objects}},
			"deny s3:GetObject on "+objects+" to "+role+" in the bucket policy")
	}
}

// decrypt: kms:Decrypt of the key for the protected bucket's data, with the
// encryption context S3 sends (DESIGN.md §9.1).
func (x *context) decrypt() {
	key, role := x.to(), x.from()
	bucket := x.g.Node(x.e.For).Identity
	cond, ok := x.context(bucket)
	if !ok {
		x.todo("bucket %s is not in the input: the encryption context it sends is not known", bucket)
		return
	}
	t := &target{action: "kms:Decrypt", principal: role, context: bucket}
	if x.fix.Side == graph.SideIdentity {
		x.policySide(t, &model.StatementInput{Action: []string{"kms:Decrypt"}, Resource: []string{key}, Conditions: []model.Condition{cond}},
			"deny kms:Decrypt of "+key+" for "+bucket+"'s data to "+role)
		return
	}
	x.policySide(t, &model.StatementInput{Principal: awsPrincipal(role), Action: []string{"kms:Decrypt"}, Resource: []string{"*"}, Conditions: []model.Condition{cond}},
		"deny kms:Decrypt for "+bucket+"'s data to "+role+" in the key policy")
}

// context: the kms:EncryptionContext:aws:s3:arn condition for the bucket:
// its ARN with an S3 Bucket Key, its object ARNs without one, both when the
// setting is not known (S3 User Guide › "Encryption context").
func (x *context) context(bucket string) (model.Condition, bool) {
	b := x.resource(bucket)
	if b == nil {
		return model.Condition{}, false
	}
	if b.Kind() != model.KindS3Bucket {
		// A secret or a parameter: its service sends its ARN (DESIGN.md 7.3).
		return model.NewCondition("StringEquals", model.EncryptionContextKey(bucket), []string{bucket}), true
	}
	const key = "kms:EncryptionContext:aws:s3:arn"
	switch b.Encryption().BucketKey {
	case model.True:
		return model.NewCondition("StringEquals", key, []string{bucket}), true
	case model.False:
		return model.NewCondition("StringLike", key, []string{bucket + "/*"}), true
	case model.Unknown:
	}
	return model.NewCondition("StringLike", key, []string{bucket, bucket + "/*"}), true
}

// assume: sts:AssumeRole on the destination role.
func (x *context) assume() {
	if x.e.Sub != "sts" {
		x.todo("no generator for %s trust fixes yet (%s); change it by hand", x.e.Sub, x.fix.Policy)
		return
	}
	dst, src := x.to(), x.from()
	t := &target{action: "sts:AssumeRole", resource: dst, principal: src}
	if x.fix.Side == graph.SideIdentity {
		x.policySide(t, &model.StatementInput{Action: []string{"sts:AssumeRole"}, Resource: []string{dst}},
			"deny sts:AssumeRole on "+dst+" to "+src)
		return
	}
	x.policySide(t, &model.StatementInput{Principal: awsPrincipal(src), Action: []string{"sts:AssumeRole"}},
		"deny sts:AssumeRole to "+src+" in "+dst+"'s trust policy")
}

// nodeRole: IMDSv2 with hop limit 1 for a pod without hostNetwork; for a
// hostNetwork pod, turning the endpoint off (or removing hostNetwork when
// the node already keeps pods out). Sources: SCORING.md §4.1.
func (x *context) nodeRole() {
	w := x.workload(x.e.From)
	ng := x.nodeGroup(x.to(), w)
	if w == nil || ng == nil {
		x.todo("the workload or its node group is not in the input")
		return
	}
	switch {
	case x.fix.Side == graph.SideWorkload:
		x.change.Edits = []Edit{{Op: OpRemoveHostNetwork, Workload: w}}
		x.change.Why = "remove hostNetwork from " + w.Identity() + ": its pods leave the node's network namespace"
	case x.fix.Kind == graph.FixRevoke:
		x.change.Edits = []Edit{{Op: OpNodeMetadata, NodeGroup: ng, Endpoint: "disabled"}}
		x.change.Why = "turn the instance metadata endpoint off for node group " + ng.Name
	default:
		x.change.Edits = []Edit{{Op: OpNodeMetadata, NodeGroup: ng, Tokens: "required", HopLimit: 1}}
		x.change.Why = "require IMDSv2 with a hop limit of 1 for node group " + ng.Name
	}
}

// tokenMount: the pod stops mounting its service account's Kubernetes
// token (automountServiceAccountToken: false); its cloud identity (IRSA,
// Pod Identity) does not need it (DESIGN.md 7.2).
func (x *context) tokenMount() {
	w := x.workload(x.e.From)
	if w == nil {
		x.todo("the workload is not in the input")
		return
	}
	x.change.Edits = []Edit{{Op: OpDisableTokenMount, Workload: w}}
	x.change.Why = "set automountServiceAccountToken: false in " + w.Identity() + ": its pods no longer hold their service account's Kubernetes token"
}

// exposure: the Service stops exposing the workload outside the cluster.
func (x *context) exposure() {
	w := x.e.To
	for _, ex := range x.in.Inventory.Exposures {
		if x.g.Node(w).ID == ex.Workload() && ex.Via() == x.e.Sub {
			if !strings.HasPrefix(ex.Via(), "Service/") {
				x.todo("remove the %s exposure %s by hand", ex.Via(), ex.Source().String())
				return
			}
			x.change.Edits = []Edit{{Op: OpRemoveExposure, Exposure: ex}}
			x.change.Why = "make " + ex.Source().Address() + " a ClusterIP Service: the workload is no longer reachable from outside the cluster"
			return
		}
	}
	x.todo("the exposure is not in the input")
}

func awsPrincipal(arn string) *model.PrincipalSpec {
	return model.NewPrincipalSpec(false, []model.PrincipalRef{{Type: model.PrincipalAWS, Value: arn}})
}

func (x *context) resource(arn string) *model.Resource {
	for _, r := range x.in.Inventory.Resources {
		if r.ARN() == arn {
			return r
		}
	}
	return nil
}

func (x *context) workload(n graph.NodeID) *model.Workload {
	for _, w := range x.in.Inventory.Workloads {
		if w.ID() == x.g.Node(n).ID {
			return w
		}
	}
	return nil
}

func (x *context) nodeGroup(role string, w *model.Workload) *model.NodeGroup {
	if w == nil {
		return nil
	}
	for _, ng := range x.in.Inventory.NodeGroups {
		if ng.RoleARN == role && ng.Cluster == w.Cluster() {
			return ng
		}
	}
	return nil
}
