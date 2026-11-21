package app

import (
	"context"
	"fmt"
	"path"

	"github.com/r3oof-900/clapa/internal/access"
	"github.com/r3oof-900/clapa/internal/classify"
	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/awslive"
	"github.com/r3oof-900/clapa/internal/collect/awsraw"
	"github.com/r3oof-900/clapa/internal/collect/awssnapshot"
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
)

// Inputs lists what to scan; paths are slash-separated, relative to Root.
type Inputs struct {
	Root           string
	TerraformPlans []PlanInput
	TerraformDirs  []string
	K8sDirs        []K8sDir
	AWSSnapshots   []string
	// AWSLive, when set, collects AWS live (read-only; --live-aws).
	AWSLive      *AWSLive
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
	// Notes say what a scan of AWS could not decide (managed policies
	// missing from the snapshot, services whose coverage is incomplete).
	Notes []access.Note
	// Collected counts the inputs that produced data. Zero means the scan
	// saw nothing (exit code 3), never "0 findings".
	Collected int
}

// Load collects every input and normalizes it into one inventory.
func Load(ctx context.Context, in *Inputs) (*Loaded, error) {
	mp, mpErr := managedpolicies.Load()
	if mpErr != nil {
		return nil, mpErr
	}
	rec := &coverage.Recorder{}
	b := normalize.NewBuilder()
	collected := 0
	tfOpts := terraformOptions(in.Config)
	for _, p := range in.TerraformPlans {
		m, err := plan.Collect(ctx, input(in, p.Path), &plan.Options{TerraformBin: in.TerraformBin, ConfigDir: p.ConfigDir}, rec)
		if err != nil {
			return nil, err
		}
		normtf.Normalize(m, tfOpts, mp, b, rec)
		collected += len(m.Resources)
	}
	for _, d := range in.TerraformDirs {
		m, err := hclstatic.Collect(ctx, input(in, d), rec)
		if err != nil {
			return nil, err
		}
		normtf.Normalize(m, tfOpts, mp, b, rec)
		collected += len(m.Resources)
	}
	for _, d := range in.K8sDirs {
		objs, err := manifests.Collect(ctx, input(in, d.Path), &manifests.Options{Cluster: d.Cluster}, rec)
		if err != nil {
			return nil, err
		}
		normk8s.Normalize(objs, b, rec)
		collected += len(objs.Items)
	}
	var notes []access.Note
	aws := &awsraw.Snapshot{}
	for _, s := range in.AWSSnapshots {
		snap, err := awssnapshot.Collect(ctx, input(in, s), rec)
		if err != nil {
			return nil, err
		}
		normaws.Normalize(snap, mp, b, rec)
		collected += len(snap.Accounts)
		aws.Accounts = append(aws.Accounts, snap.Accounts...)
	}
	if in.AWSLive != nil {
		snap, err := awslive.Collect(ctx, in.AWSLive, rec)
		if err != nil {
			return nil, err
		}
		normaws.Normalize(snap, mp, b, rec)
		collected += len(snap.Accounts)
		aws.Accounts = append(aws.Accounts, snap.Accounts...)
	}
	if len(in.AWSSnapshots) > 0 || in.AWSLive != nil {
		notes = awsNotes(aws, mp)
	}
	addConfiguredClusters(in.Config, b)
	inv, err := b.Build()
	if err != nil {
		return nil, fmt.Errorf("normalize: %w", err)
	}
	inv.Resources = classify.CrownJewels(inv.Resources, jewelRules(in.Config))
	return &Loaded{
		Inventory: inv, EntryPoints: classify.EntryPoints(inv, *in.Config.ThreatModel.AssumeCompromised),
		Gaps: rec.Gaps(), Notes: notes, Collected: collected,
	}, nil
}

func input(in *Inputs, p string) *collect.Input {
	return &collect.Input{Root: in.Root, Path: path.Clean(p), Limits: in.Limits}
}

func terraformOptions(c *config.Config) *normtf.Options {
	issuers := map[string]string{}
	for _, cl := range c.Clusters {
		issuers[cl.Name] = cl.OIDCIssuer
	}
	return &normtf.Options{Account: c.Terraform.Account, Region: c.Terraform.Region, Partition: c.Terraform.Partition, OIDCIssuers: issuers}
}

// addConfiguredClusters adds clusters declared only in clapa.yaml (e.g. a
// cluster whose manifests are scanned without its Terraform).
func addConfiguredClusters(c *config.Config, b *normalize.Builder) {
	for _, cl := range c.Clusters {
		if !b.Has(model.NewID("cluster", cl.Name)) {
			b.AddCluster(&model.Cluster{
				Name: cl.Name, Account: cl.Account, Region: cl.Region, OIDCIssuer: cl.OIDCIssuer,
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
