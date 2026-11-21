package live

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// docs/PERMISSIONS.md's ClusterRole grants exactly what the collector
// calls: list on every listed kind and on secrets, get on aws-auth only.
func TestK8sPermissionsDocument(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "PERMISSIONS.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "```yaml")
	block, _, ok2 := strings.Cut(rest, "```")
	if !ok || !ok2 {
		t.Fatal("docs/PERMISSIONS.md has no yaml ClusterRole block")
	}
	var role rbacv1.ClusterRole
	if err := yaml.NewYAMLOrJSONDecoder(strings.NewReader(block), 4096).Decode(&role); err != nil {
		t.Fatal(err)
	}
	granted := map[string]bool{}
	for _, r := range role.Rules {
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				for _, v := range r.Verbs {
					key := g + "/" + res + " " + v
					if len(r.ResourceNames) > 0 {
						key += " " + strings.Join(r.ResourceNames, ",")
					}
					granted[key] = true
				}
			}
		}
	}
	want := map[string]bool{"/secrets list": true, "/configmaps get aws-auth": true}
	for _, k := range kinds() {
		want[k.gvk.Group+"/"+k.resource+" list"] = true
	}
	var missing, extra []string
	for k := range want {
		if !granted[k] {
			missing = append(missing, k)
		}
	}
	for k := range granted {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	slices.Sort(missing)
	slices.Sort(extra)
	if len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("PERMISSIONS.md ClusterRole: missing %v, not used %v", missing, extra)
	}
}
