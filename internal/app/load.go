package app

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/access"
	"github.com/r3oof-900/clapa/internal/classify"
	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/awslive"
	"github.com/r3oof-900/clapa/internal/collect/awsraw"
	"github.com/r3oof-900/clapa/internal/collect/awssnapshot"
	"github.com/r3oof-900/clapa/internal/collect/k8s/live"
	"github.com/r3oof-900/clapa/internal/collect/k8s/manifests"
	"github.com/r3oof-900/clapa/internal/collect/terraform/hclstatic"
	"github.com/r3oof-900/clapa/internal/collect/terraform/plan"
	"github.com/r3oof-900/clapa/internal/config"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/managedpolicies"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/normalize"
	normaws "github.com/r3oof-900/clapa/internal/normalize/aws"
	normk8s "github.com/r3oof-900/clapa/internal/normalize/k8s"
	normtf "github.com/r3oof-900/clapa/internal/normalize/terraform"
	"github.com/r3oof-900/clapa/internal/safeio"
	"github.com/r3oof-900/clapa/pkg/schema"
)

// Inputs lists what to scan; paths are slash-separated, relative to Root.
type Inputs struct {
	Root           string
	TerraformPlans []PlanInput
	TerraformDirs  []string
	K8sDirs        []K8sDir
	AWSSnapshots   []string
	// AWSLive, when set, collects AWS live (read-only; --live-aws).
	AWSLive *AWSLive
	// K8sLive are live clusters (--live-k8s, --k8s-eks).
	K8sLive      []K8sLive
	Config       *config.Config
	Limits       safeio.Limits
	TerraformBin string
}

// PlanInput is a Terraform plan and, when known, the root module directory it
// was made from (used only to verify for_each sets; see the plan collector).
type PlanInput struct {
	Path      string
	ConfigDir string
}

// K8sDir is a manifest directory and the cluster it describes.
type K8sDir struct {
	Path    string
	Cluster string
}

// Loaded is the result of collection and normalization.
type Loaded struct {
	Inventory   *model.Inventory
	EntryPoints []classify.EntryPoint
	Gaps        []coverage.Gap
	// Intended is clapa.yaml's intended_access with every Kubernetes
	// principal written with its cluster key (resolveIdentities).
	Intended []config.IntendedAccess
	// Notes say what a scan of AWS could not decide (managed policies
	// missing from the snapshot, services whose coverage is incomplete).
	Notes []access.Note
	// Collected counts the inputs that produced data. Zero means the scan
	// saw nothing (exit code 3), never "0 findings".
	Collected int
	// Inputs: what was scanned, with digests (the report's inputs).
	Inputs []schema.ScannedInput
}

// Load collects every input and normalizes it into one inventory.
func Load(ctx context.Context, in *Inputs) (*Loaded, error) {
	mp, err := managedpolicies.Load()
	if err != nil {
		return nil, err
	}
	l := &loader{in: in, mp: mp, rec: &coverage.Recorder{}, b: normalize.NewBuilder()}
	// Kubernetes last: its cluster names resolve against the clusters
	// Terraform, AWS and clapa.yaml describe (clusterKey).
	for _, step := range []func(context.Context) error{l.terraform, l.aws, l.kubernetes} {
		if serr := step(ctx); serr != nil {
			return nil, serr
		}
	}
	l.keysOutsideInput()
	addConfiguredClusters(in.Config, l.b)
	inv, err := l.b.Build()
	if err != nil {
		return nil, fmt.Errorf("normalize: %w", err)
	}
	inv.Resources = classify.CrownJewels(inv.Resources, jewelRules(in.Config))
	intended, err := resolveIdentities(inv, in.Config)
	if err != nil {
		return nil, err
	}
	return &Loaded{
		Intended:  intended,
		Inventory: inv, EntryPoints: classify.EntryPoints(inv, *in.Config.ThreatModel.AssumeCompromised),
		Gaps: l.rec.Gaps(), Notes: l.notes, Collected: l.collected, Inputs: l.inputs,
	}, nil
}

// loader collects the inputs into one builder.
type loader struct {
	in        *Inputs
	mp        *managedpolicies.Snapshot
	rec       *coverage.Recorder
	b         *normalize.Builder
	notes     []access.Note
	collected int
	inputs    []schema.ScannedInput
}

func (l *loader) terraform(ctx context.Context) error {
	in := l.in
	opts := terraformOptions(in.Config)
	for _, p := range in.TerraformPlans {
		m, err := plan.Collect(ctx, input(in, p.Path), &plan.Options{TerraformBin: in.TerraformBin, ConfigDir: p.ConfigDir}, l.rec)
		if err != nil {
			return err
		}
		normtf.Normalize(m, opts, l.mp, l.b, l.rec)
		l.collected += len(m.Resources)
		l.recordFiles(inputTerraformPlan, p.Path, "", nil)
	}
	for _, d := range in.TerraformDirs {
		m, err := hclstatic.Collect(ctx, input(in, d), l.rec)
		if err != nil {
			return err
		}
		normtf.Normalize(m, opts, l.mp, l.b, l.rec)
		l.collected += len(m.Resources)
		l.recordFiles(inputTerraformDir, d, "", nil)
	}
	return nil
}

func (l *loader) kubernetes(ctx context.Context) error {
	for _, k := range l.in.K8sLive {
		key, err := l.clusterKey(k.Cluster)
		if err != nil {
			return err
		}
		objs, err := live.Collect(ctx, &live.Options{Cluster: key, Clients: k.Clients}, l.rec)
		if err != nil {
			return err
		}
		normk8s.Normalize(objs, l.b, l.rec)
		l.collected += len(objs.Items)
		l.recordLive(inputK8sLive, key, nil, nil, objs)
		if k.Clients.Insecure {
			l.notes = append(l.notes, insecureNote(key))
		}
	}
	for _, d := range l.in.K8sDirs {
		key, err := l.clusterKey(d.Cluster)
		if err != nil {
			return err
		}
		objs, err := manifests.Collect(ctx, input(l.in, d.Path), &manifests.Options{Cluster: key}, l.rec)
		if err != nil {
			return err
		}
		normk8s.Normalize(objs, l.b, l.rec)
		l.collected += len(objs.Items)
		l.recordFiles(inputK8sManifests, d.Path, key, nil)
	}
	return nil
}

// ErrAmbiguousCluster is returned when a cluster name given for
// Kubernetes input matches several clusters.
var ErrAmbiguousCluster = errors.New("ambiguous cluster")

// clusterKey resolves the cluster a Kubernetes input names (--k8s
// DIR=CLUSTER, --live-k8s CONTEXT=CLUSTER) to its key (model.ClusterKey):
// an ARN is the key; a name is looked up in clapa.yaml and in the clusters
// Terraform and AWS describe, and must match one cluster (two clusters of
// one name need the ARN); a name nothing describes is its own key. No name
// means the one configured cluster, or DefaultClusterName.
func (l *loader) clusterKey(name string) (string, error) {
	cfg := l.in.Config
	if name == "" {
		switch len(cfg.Clusters) {
		case 0:
			return model.DefaultClusterName, nil
		case 1:
			name = cfg.Clusters[0].Name
		default:
			return "", fmt.Errorf("%w: %w: clapa.yaml declares %d clusters: name the cluster of each Kubernetes input (DIR=CLUSTER)",
				config.ErrInvalid, ErrAmbiguousCluster, len(cfg.Clusters))
		}
	}
	if model.IsClusterARN(name) {
		return name, nil
	}
	keys := l.b.ClusterKeys(name)
	for i := range cfg.Clusters {
		if cl := &cfg.Clusters[i]; cl.Name == name && !slices.Contains(keys, cl.Key(cfg.Terraform.Partition)) {
			keys = append(keys, cl.Key(cfg.Terraform.Partition))
		}
	}
	switch len(keys) {
	case 0:
		return name, nil
	case 1:
		return keys[0], nil
	}
	slices.Sort(keys)
	return "", fmt.Errorf("%w: %w: cluster name %q matches %d clusters (%s): give the cluster's ARN (DIR=ARN, CONTEXT=ARN)",
		config.ErrInvalid, ErrAmbiguousCluster, name, len(keys), strings.Join(keys, ", "))
}

func (l *loader) aws(ctx context.Context) error {
	all := &awsraw.Snapshot{}
	add := func(snap *awsraw.Snapshot) {
		normaws.Normalize(snap, l.mp, l.b, l.rec)
		l.collected += len(snap.Accounts)
		all.Accounts = append(all.Accounts, snap.Accounts...)
	}
	for _, s := range l.in.AWSSnapshots {
		snap, err := awssnapshot.Collect(ctx, input(l.in, s), l.rec)
		if err != nil {
			return err
		}
		add(snap)
		l.recordFiles(inputAWSSnapshot, s, "", accountsOf(snap))
	}
	if l.in.AWSLive != nil {
		snap, err := awslive.Collect(ctx, l.in.AWSLive, l.rec)
		if err != nil {
			return err
		}
		add(snap)
		l.recordLive(inputAWSLive, "", accountsOf(snap), l.in.AWSLive.Regions, snap)
	}
	if len(l.in.AWSSnapshots) > 0 || l.in.AWSLive != nil {
		l.notes = append(l.notes, awsNotes(all, l.mp)...)
	}
	return nil
}

func input(in *Inputs, p string) *collect.Input {
	return &collect.Input{Root: in.Root, Path: path.Clean(p), Limits: in.Limits}
}

func terraformOptions(c *config.Config) *normtf.Options {
	issuers := map[string]string{}
	for i := range c.Clusters {
		issuers[c.Clusters[i].Key(c.Terraform.Partition)] = c.Clusters[i].OIDCIssuer
	}
	return &normtf.Options{Account: c.Terraform.Account, Region: c.Terraform.Region, Partition: c.Terraform.Partition, OIDCIssuers: issuers}
}

// addConfiguredClusters adds clusters declared only in clapa.yaml (e.g. a
// cluster whose manifests are scanned without its Terraform).
func addConfiguredClusters(c *config.Config, b *normalize.Builder) {
	for _, cl := range c.Clusters {
		arn := model.EKSClusterARN(c.Terraform.Partition, cl.Region, cl.Account, cl.Name)
		if !b.Has(model.NewID("cluster", model.ClusterKey(arn, cl.Name))) {
			b.AddCluster(&model.Cluster{
				Name: cl.Name, ARN: arn, Account: cl.Account, Region: cl.Region, OIDCIssuer: cl.OIDCIssuer,
				Source: model.FileLocation("clapa.yaml", 0, 0, "clusters."+cl.Name),
			})
		}
	}
}

func jewelRules(c *config.Config) *classify.Rules {
	r := &classify.Rules{TagKeys: c.CrownJewels.TagKeys, TagValues: c.CrownJewels.TagValues, Explicit: map[string]string{}}
	for _, e := range c.CrownJewels.Explicit {
		r.Explicit[e.ARN] = e.Classification
	}
	return r
}
