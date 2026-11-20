package plan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/tfraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/safeio"
)

// Name identifies this collector in coverage gaps.
const Name = "terraform-plan"

// ErrNotJSON is returned for a binary plan file when no terraform binary is
// configured or found.
var ErrNotJSON = errors.New("plan: input is not plan JSON")

// Options configure the collector.
type Options struct {
	// TerraformBin converts binary plan files with "terraform show -json".
	// Empty: look up "terraform" on PATH. Never used for JSON input.
	TerraformBin string
}

// Collect reads a plan (JSON from "terraform show -json", or a binary plan
// file) and returns its resources. Values only known after apply become
// symbolic references when the configuration names the referenced
// attribute, else KUnknownAfterApply; each such value is a coverage gap.
func Collect(ctx context.Context, in *collect.Input, opts *Options, rec *coverage.Recorder) (*tfraw.Module, error) {
	data, err := safeio.ReadFile(in.Root, in.Path, in.Limits)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if first := bytes.TrimLeft(data, " \t\r\n"); len(first) == 0 || first[0] != '{' {
		if data, err = showJSON(ctx, in, opts); err != nil {
			return nil, err
		}
	}
	if err := safeio.CheckJSONDepth(data, in.Limits.MaxDepth); err != nil {
		return nil, fmt.Errorf("%s: %s: %w", Name, in.Path, err)
	}
	var p tfjson.Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("%s: %s: %w", Name, in.Path, err)
	}
	c := &converter{file: in.Path, rec: rec, changes: map[string]*tfjson.ResourceChange{}, configs: map[string]*tfjson.ConfigResource{}}
	c.index(&p)
	m := &tfraw.Module{Source: "plan"}
	if p.PlannedValues != nil {
		m.Resources = c.module(p.PlannedValues.RootModule, nil)
	}
	if p.PriorState != nil && p.PriorState.Values != nil {
		m.Resources = append(m.Resources, c.module(p.PriorState.Values.RootModule, dataOnly(m.Resources))...)
	}
	m.Providers = providers(&p)
	m.Sort()
	return m, nil
}

// dataOnly returns a filter that admits data sources not already present.
func dataOnly(have []*tfraw.Resource) func(*tfjson.StateResource) bool {
	seen := map[string]bool{}
	for _, r := range have {
		seen[r.Address] = true
	}
	return func(sr *tfjson.StateResource) bool {
		return sr.Mode == tfjson.DataResourceMode && !seen[sr.Address]
	}
}

type converter struct {
	file    string
	rec     *coverage.Recorder
	changes map[string]*tfjson.ResourceChange // by full address
	configs map[string]*tfjson.ConfigResource // by module path + config address
}

func (c *converter) index(p *tfjson.Plan) {
	for _, rc := range p.ResourceChanges {
		c.changes[rc.Address] = rc
	}
	if p.Config != nil {
		c.indexConfig("", p.Config.RootModule)
	}
}

func (c *converter) indexConfig(prefix string, m *tfjson.ConfigModule) {
	if m == nil {
		return
	}
	for _, r := range m.Resources {
		c.configs[join(prefix, r.Address)] = r
	}
	for _, name := range sortedKeys(m.ModuleCalls) {
		c.indexConfig(join(prefix, "module."+name), m.ModuleCalls[name].Module)
	}
}

func (c *converter) module(m *tfjson.StateModule, keep func(*tfjson.StateResource) bool) []*tfraw.Resource {
	if m == nil {
		return nil
	}
	var out []*tfraw.Resource
	for _, sr := range m.Resources {
		if keep == nil || keep(sr) {
			out = append(out, c.resource(m.Address, sr))
		}
	}
	for _, child := range m.ChildModules {
		out = append(out, c.module(child, keep)...)
	}
	return out
}

func (c *converter) resource(module string, sr *tfjson.StateResource) *tfraw.Resource {
	r := &tfraw.Resource{
		Address: sr.Address, Mode: string(sr.Mode), Type: sr.Type, Name: sr.Name, Module: module,
		Index: indexKey(sr.Index), Provider: sr.ProviderName, Root: c.file, Pos: tfraw.Pos{File: c.file},
	}
	var unknown any
	if rc, ok := c.changes[sr.Address]; ok && rc.Change != nil {
		unknown = rc.Change.AfterUnknown
	}
	cfg := c.configs[r.ConfigAddress()]
	r.Attrs = c.object(sr.AttributeValues, unknown, cfg, r)
	return r
}

func indexKey(idx any) string {
	switch v := idx.(type) {
	case nil:
		return ""
	case string:
		return fmt.Sprintf("%q", v)
	}
	return fmt.Sprint(idx)
}

func join(prefix, s string) string {
	if prefix == "" {
		return s
	}
	return prefix + "." + s
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func providers(p *tfjson.Plan) []*tfraw.Provider {
	if p.Config == nil {
		return nil
	}
	var out []*tfraw.Provider
	for _, key := range sortedKeys(p.Config.ProviderConfigs) {
		pc := p.Config.ProviderConfigs[key]
		if pc.Name != "aws" && !strings.HasSuffix(pc.Name, "/aws") {
			continue
		}
		out = append(out, &tfraw.Provider{Key: key, Region: constant(pc.Expressions["region"])})
	}
	return out
}

func constant(e *tfjson.Expression) *tfraw.Value {
	if e == nil || e.ExpressionData == nil {
		return nil
	}
	if s, ok := e.ConstantValue.(string); ok {
		return tfraw.String(s)
	}
	return nil
}
