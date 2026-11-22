package app

import (
	"fmt"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/model"
)

// The RAM note names the SSM parameters that are, may become or may be
// advanced-tier (only those can be shared through AWS RAM); with none,
// there is no note.
func TestRAMNote(t *testing.T) {
	param := func(name, tier string) *model.Resource {
		return model.NewResource(&model.ResourceInput{Kind: model.KindSSMParameter, ARN: "arn:aws:ssm:us-east-1:111122223333:parameter/" + name, Tier: tier})
	}
	bucket := model.NewResource(&model.ResourceInput{Kind: model.KindS3Bucket, ARN: "arn:aws:s3:::b"})
	if _, ok := ramNote(&model.Inventory{Resources: []*model.Resource{param("std", "Standard"), bucket}}); ok {
		t.Fatal("a note without a shareable parameter")
	}
	n, ok := ramNote(&model.Inventory{Resources: []*model.Resource{
		param("std", "Standard"), param("adv", "Advanced"), param("it", "Intelligent-Tiering"), param("unknown", ""),
	}})
	if !ok || strings.Contains(n.Detail, "/std") || !strings.Contains(n.Detail, "parameter/adv (Advanced)") ||
		!strings.Contains(n.Detail, "parameter/it (Intelligent-Tiering)") || !strings.Contains(n.Detail, "parameter/unknown (tier unknown)") {
		t.Fatalf("note %+v", n)
	}
	var many []*model.Resource
	for i := range 12 {
		many = append(many, param(fmt.Sprint("p", i), "Advanced"))
	}
	if n, _ := ramNote(&model.Inventory{Resources: many}); !strings.HasSuffix(n.Detail, " and 2 more") {
		t.Errorf("long list: %s", n.Detail)
	}
}
