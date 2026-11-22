package classify

import (
	"testing"

	"github.com/r3oof-900/darb/internal/model"
)

func res(kind model.NodeKind, arn string, tags map[string]string) *model.Resource {
	return model.NewResource(&model.ResourceInput{Kind: kind, ARN: arn, Tags: tags})
}

func TestCrownJewels(t *testing.T) {
	rules := &Rules{TagKeys: []string{"DataClass"}, TagValues: []string{"pii", "pci"}, Explicit: map[string]string{"arn:aws:s3:::explicit": "phi"}}
	in := []*model.Resource{
		res(model.KindS3Bucket, "arn:aws:s3:::tagged", map[string]string{"dataclass": "PII"}),
		res(model.KindS3Bucket, "arn:aws:s3:::explicit", nil),
		res(model.KindSecret, "arn:aws:secretsmanager:r:1:secret:s", map[string]string{"Classification": "sensitive"}),
		res(model.KindKMSKey, "arn:aws:kms:r:1:key/k", map[string]string{"sensitive": "TRUE"}),
		res(model.KindS3Bucket, "arn:aws:s3:::plain", map[string]string{"DataClass": "public"}),
		res(model.KindEC2Instance, "arn:aws:ec2:r:1:instance/i", map[string]string{"DataClass": "pii"}),
	}
	want := []struct{ class, by string }{
		{"pii", "tag:dataclass"},
		{"phi", "config:crown_jewels.explicit"},
		{"sensitive", "heuristic:tagged-sensitive"},
		{"sensitive", "heuristic:tagged-sensitive"},
		{"", ""},
		{"", ""}, // not a data resource
	}
	out := CrownJewels(in, rules)
	for i, w := range want {
		class, by := out[i].Classification()
		if class != w.class || by != w.by {
			t.Errorf("%s: %q by %q, want %q by %q", out[i].ARN(), class, by, w.class, w.by)
		}
	}
	if c, _ := in[0].Classification(); c != "" {
		t.Error("classification returns new resources; inputs are not mutated")
	}
}

func TestEntryPoints(t *testing.T) {
	s := model.FileLocation("f", 1, 1, "")
	exposed := model.NewWorkload(&model.WorkloadInput{Cluster: "c", Namespace: "n", Kind: "Deployment", Name: "web", Source: s})
	internal := model.NewWorkload(&model.WorkloadInput{Cluster: "c", Namespace: "n", Kind: "Deployment", Name: "batch", Source: s})
	inv := &model.Inventory{
		Workloads: []*model.Workload{exposed, internal},
		Exposures: []*model.NetworkExposure{
			model.NewNetworkExposure(exposed.ID(), "Service/LoadBalancer", model.True, &s),
			model.NewNetworkExposure(exposed.ID(), "Service/LoadBalancer", model.True, &s), // same exposure twice
		},
	}
	if eps := EntryPoints(inv, false); len(eps) != 1 || eps[0].Reason != "exposed:Service/LoadBalancer" {
		t.Errorf("exposed only: %+v", eps)
	}
	eps := EntryPoints(inv, true)
	if len(eps) != 2 {
		t.Fatalf("assume compromised: %+v", eps)
	}
	for _, e := range eps {
		if e.Workload == internal.ID() && (e.Reason != "assume-compromised" || e.Public != model.Unknown) {
			t.Errorf("internal workload %+v", e)
		}
	}
}
