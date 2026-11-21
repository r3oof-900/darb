package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	yamlv3 "go.yaml.in/yaml/v3"
	"sigs.k8s.io/yaml"

	"github.com/r3oof-900/clapa/internal/arn"
	"github.com/r3oof-900/clapa/internal/model"
)

// ErrInvalid is returned for configuration that fails validation (exit code 2).
var ErrInvalid = errors.New("config: invalid configuration")

// Config is clapa.yaml. Every field is documented in docs/DESIGN.md.
type Config struct {
	Version        int                 `json:"version"`
	Terraform      Terraform           `json:"terraform"`
	Clusters       []Cluster           `json:"clusters"`
	CrownJewels    CrownJewels         `json:"crown_jewels"`
	ThreatModel    ThreatModel         `json:"threat_model"`
	Assume         map[string][]string `json:"assume"` // context-key assumptions, e.g. aws:PrincipalOrgID
	IntendedAccess []IntendedAccess    `json:"intended_access"`
	Remediation    Remediation         `json:"remediation"`
	Coverage       Coverage            `json:"coverage"`
}

// Terraform says where Terraform resources live when the input does not.
type Terraform struct {
	Account   string `json:"account"`
	Region    string `json:"region"`
	Partition string `json:"partition"`
}

// Cluster identifies a Kubernetes cluster and its IRSA OIDC issuer.
type Cluster struct {
	Name       string `json:"name"`
	Account    string `json:"account"`
	Region     string `json:"region"`
	OIDCIssuer string `json:"oidc_issuer"` // e.g. https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE
}

// CrownJewels configures what counts as sensitive data.
type CrownJewels struct {
	TagKeys   []string        `json:"tag_keys"`
	TagValues []string        `json:"tag_values"`
	Explicit  []ExplicitJewel `json:"explicit"`
}

// ExplicitJewel marks one resource by ARN.
type ExplicitJewel struct {
	ARN            string `json:"arn"`
	Classification string `json:"classification"`
}

// ThreatModel selects the entry-point model.
type ThreatModel struct {
	AssumeCompromised *bool `json:"assume_compromised"` // default true
}

// IntendedAccess is access that must survive any remediation.
type IntendedAccess struct {
	Principal string `json:"principal"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
}

// Remediation configures cut costs (docs/SCORING.md section 4).
type Remediation struct {
	CutCosts        map[string]int   `json:"cut_costs"`
	UncuttableEdges []UncuttableEdge `json:"uncuttable_edges"`
}

// UncuttableEdge forbids cutting matching edges.
type UncuttableEdge struct {
	Kind   string `json:"kind"`
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
}

// Coverage sets how many gaps of each kind are tolerated before exit code 3.
type Coverage struct {
	Tolerance map[string]int `json:"tolerance"`
}

// Default returns the configuration used when no clapa.yaml is given.
func Default() *Config {
	yes := true
	return &Config{
		Version:     1,
		Terraform:   Terraform{Partition: "aws"},
		CrownJewels: CrownJewels{TagKeys: []string{"DataClass"}, TagValues: []string{"pii", "pci", "phi", "secret"}},
		ThreatModel: ThreatModel{AssumeCompromised: &yes},
	}
}

// Parse decodes and validates clapa.yaml. Unknown fields are errors, so a
// typo cannot silently disable a setting.
func Parse(data []byte) (*Config, error) {
	c := Default()
	if line, found := reservedLine(data); found {
		return nil, fmt.Errorf("%w: clapa.yaml:%d contains the reserved text %s...}", ErrInvalid, line, model.UnresolvedPrefix)
	}
	if err := yaml.UnmarshalStrict(data, c); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if c.ThreatModel.AssumeCompromised == nil {
		yes := true
		c.ThreatModel.AssumeCompromised = &yes
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	if c.Version != 1 {
		add("version must be 1, got %d", c.Version)
	}
	if c.Terraform.Account != "" && !arn.IsAccountID(c.Terraform.Account) {
		add("terraform.account %q is not a 12-digit account ID", c.Terraform.Account)
	}
	c.validateClusters(add)
	c.validateAccess(add)
	for k, v := range c.Coverage.Tolerance {
		if v < 0 {
			add("coverage.tolerance.%s must be >= 0", k)
		}
	}
	if len(problems) > 0 {
		slices.Sort(problems)
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}

// validateAccess checks intended access and remediation constraints.
func (c *Config) validateAccess(add func(string, ...any)) {
	for i, ia := range c.IntendedAccess {
		if ia.Principal == "" || ia.Action == "" || ia.Resource == "" {
			add("intended_access[%d]: principal, action and resource are required", i)
		}
	}
	for k, v := range c.Remediation.CutCosts {
		if v < 1 {
			add("remediation.cut_costs.%s must be >= 1", k)
		}
	}
	for i, u := range c.Remediation.UncuttableEdges {
		if u.Kind == "" || u.From == "" || u.To == "" || u.Reason == "" {
			add("remediation.uncuttable_edges[%d]: kind, from, to and reason are required", i)
		}
	}
}

func (c *Config) validateClusters(add func(string, ...any)) {
	seen := map[string]bool{}
	for i, cl := range c.Clusters {
		key := cl.Key(c.Terraform.Partition)
		switch {
		case cl.Name == "":
			add("clusters[%d]: name is required", i)
		case seen[key]:
			add("clusters[%d]: duplicate cluster %q (two clusters of one name need different accounts or regions)", i, key)
		}
		seen[key] = true
		if cl.Account != "" && !arn.IsAccountID(cl.Account) {
			add("clusters[%d]: account %q is not a 12-digit account ID", i, cl.Account)
		}
		if cl.OIDCIssuer != "" && !strings.HasPrefix(cl.OIDCIssuer, "https://") {
			add("clusters[%d]: oidc_issuer must start with https://", i)
		}
	}
}

// Key is the cluster's identity (model.ClusterKey): its ARN when the
// account and region are set, otherwise its name.
func (cl *Cluster) Key(partition string) string {
	return model.ClusterKey(model.EKSClusterARN(partition, cl.Region, cl.Account, cl.Name), cl.Name)
}

// Cluster returns the cluster with the given name.
func (c *Config) Cluster(name string) (Cluster, bool) {
	for _, cl := range c.Clusters {
		if cl.Name == name {
			return cl, true
		}
	}
	return Cluster{}, false
}

// reservedLine finds a key or value (as YAML decodes it) that contains the
// placeholder text only the normalizer may create (docs/DESIGN.md 4.6).
// Undecodable YAML is left to UnmarshalStrict to report.
func reservedLine(data []byte) (int, bool) {
	var doc yamlv3.Node
	if yamlv3.Unmarshal(data, &doc) != nil {
		return 0, false
	}
	return reservedNode(&doc)
}

func reservedNode(n *yamlv3.Node) (int, bool) {
	if n.Kind == yamlv3.ScalarNode && model.ContainsUnresolved(n.Value) {
		return n.Line, true
	}
	for _, c := range n.Content {
		if line, ok := reservedNode(c); ok {
			return line, true
		}
	}
	return 0, false
}
