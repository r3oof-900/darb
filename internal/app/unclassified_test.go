package app

import (
	"os"
	"path/filepath"
	"testing"
)

// Unclassified data stores (SCORING.md §1.2, decided after v0.1.0-rc.1).

const (
	vaultBucket    = "arn:aws:s3:::patient-records-vault"
	receiptsBucket = "arn:aws:s3:::acme-payment-receipts"
)

// Posture rules apply to classified jewels only: scenario 24's bucket has
// Block Public Access off, which DARB-POST-005 reports once the bucket is
// classified, and not before.
func TestPostureSkipsUnclassified(t *testing.T) {
	post005 := func(a *Analysis) bool {
		for i := range a.Findings {
			if a.Findings[i].Rule == "DARB-POST-005" && a.Findings[i].Resource == vaultBucket {
				return true
			}
		}
		return false
	}
	if post005(analyzeVariant(t, "24_unclassified_bucket/vulnerable", nil)) {
		t.Fatal("DARB-POST-005 on an unclassified bucket")
	}
	a := analyzeVariant(t, "24_unclassified_bucket/vulnerable", func(dir string) {
		appendConfig(t, dir, "crown_jewels:", "  explicit: [{arn: \""+vaultBucket+"\", classification: phi}]")
	})
	if !post005(a) {
		t.Fatal("no DARB-POST-005 once the bucket is classified: the skip is not what removes it")
	}
	// Classified phi (1000), the same path scores 324 x 1000 = 324.
	if f := findingFor(a, "DARB-PATH-001", vaultBucket); f == nil || f.Factors.Score != 324 || f.JewelClassification != "phi" {
		t.Fatalf("classified: %+v", f)
	}
}

// Blast radius counts classified jewels only. Scenario 1b without its
// intended access: api reads the PII bucket and the unclassified receipts
// bucket; the PII path keeps 729 (one classified jewel: 1000), and the
// receipts path is reported with blast radius 1000 too.
func TestBlastRadiusCountsClassifiedJewels(t *testing.T) {
	a := analyzeVariant(t, "01b_classic_intended/vulnerable", dropIntended(t))
	pii := findingFor(a, "DARB-PATH-001", piiBucket)
	receipts := findingFor(a, "DARB-PATH-001", receiptsBucket)
	if pii == nil || pii.Factors.BlastRadius != 1000 || pii.Factors.Score != 729 {
		t.Fatalf("PII: %+v", pii)
	}
	if receipts == nil || receipts.Factors.BlastRadius != 1000 || receipts.Factors.Classification != 400 || receipts.JewelClassification != "unclassified" {
		t.Fatalf("receipts: %+v", receipts)
	}
}

// A declaration of part of a bucket leaves the pair reported: the path
// reads more than was declared.
func TestIntendedPrefixKeepsThePair(t *testing.T) {
	a := analyzeVariant(t, "01b_classic_intended/vulnerable", func(dir string) {
		dropIntended(t)(dir)
		appendConfig(t, dir, "intended_access:", "  - principal: \"k8s:prod/payments/Deployment/api\"",
			"    action: \"s3:GetObject\"", "    resource: \""+receiptsBucket+"/2026/*\"")
	})
	if findingFor(a, "DARB-PATH-001", receiptsBucket) == nil {
		t.Fatal("a prefix declaration hid the pair")
	}
}

// dropIntended drops scenario 1b's intended_access from darb.yaml.
func dropIntended(t *testing.T) func(dir string) {
	return func(dir string) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(repoRoot(t), "tests", "fixtures", "01_classic", "vulnerable", "darb.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "darb.yaml"), data, 0o600); err != nil { //nolint:gosec // G703: temp copy.
			t.Fatal(err)
		}
	}
}
