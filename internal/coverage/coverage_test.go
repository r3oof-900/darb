package coverage

import "testing"

func TestRecorderSortsAndDeduplicates(t *testing.T) {
	var r, o Recorder
	r.Add(&Gap{Kind: KindUnresolved, Source: "hcl", File: "b.tf", Line: 3})
	r.Add(&Gap{Kind: KindParseError, Source: "hcl", File: "a.tf", Line: 9})
	o.Add(&Gap{Kind: KindUnresolved, Source: "hcl", File: "b.tf", Line: 3}) // duplicate
	o.Add(&Gap{Kind: KindAccessDenied, Source: "aws", Service: "kms", API: "GetKeyPolicy"})
	r.Merge(&o)
	if r.Len() != 4 || r.Count(KindUnresolved) != 2 || r.Count(KindTimeout) != 0 {
		t.Fatalf("len %d", r.Len())
	}
	g := r.Gaps()
	if len(g) != 3 || g[0].Source != "aws" || g[1].File != "a.tf" || g[2].File != "b.tf" {
		t.Fatalf("got %+v", g)
	}
}
