package app

import (
	"fmt"
	"strings"

	"github.com/r3oof-900/darb/internal/access"
	"github.com/r3oof-900/darb/internal/classify"
	"github.com/r3oof-900/darb/internal/config"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/pkg/schema"
)

// notModelled lists what the engine does not analyse yet (DESIGN.md §12.0).
// The engine is silent about these, rather than UNKNOWN, so every report
// states them.
func notModelled(inv *model.Inventory) []access.Note {
	n := func(subject, detail string) access.Note {
		return access.Note{Kind: "not-modelled", Subject: subject, Detail: detail}
	}
	notes := []access.Note{
		n(NoteAdmission, "a pod that names a Secret, or a pod created to name one, is an edge "+
			"(CAN_READ_PLAINTEXT[mount], [pod-create]); admission policies that would reject such a pod are not read"),
	}
	for _, note := range []func(*model.Inventory) (access.Note, bool){ramNote, kmsGrantsNote, s3ACLNote, organizationsNote} {
		if nt, ok := note(inv); ok {
			notes = append(notes, nt)
		}
	}
	return notes
}

// Subjects of the not-modelled notes darb writes. DESIGN.md §12.3 lists
// them, each with a scenario whose report must carry it (TestStatedLimits).
const (
	NoteKMSGrants     = "KMS grants"
	NoteS3ACLs        = "S3 ACLs"
	NoteOrganizations = "AWS Organizations SCPs and RCPs"
	NoteRAMShares     = "AWS RAM shares of SSM parameters"
	NoteAdmission     = "Kubernetes Secrets through admission"
)

// named lists what the input has of one kind, at most ten, with how many
// more.
func named(inv *model.Inventory, keep func(*model.Resource) (string, bool)) string {
	var names []string
	for _, r := range inv.Resources {
		if s, ok := keep(r); ok {
			names = append(names, s)
		}
	}
	if len(names) == 0 {
		return ""
	}
	const show = 10
	list := strings.Join(names[:min(show, len(names))], ", ")
	if len(names) > show {
		list += fmt.Sprintf(" and %d more", len(names)-show)
	}
	return list
}

// kmsGrantsNote: the keys whose grants are not all in the input (DESIGN.md
// §6, KMS grants). A grant can give kms:Decrypt to a principal the key
// policy does not name, so a path through such a key can be missed. Keys
// read from Terraform have their aws_kms_grant resources, not the grants
// AWS services create at runtime; keys whose ListGrants failed (a gap too),
// whose snapshot predates it, or that are not in the input have none. A key whose grants were listed
// is not named.
func kmsGrantsNote(inv *model.Inventory) (access.Note, bool) {
	key := func(state string) func(*model.Resource) (string, bool) {
		return func(r *model.Resource) (string, bool) {
			return r.ARN(), r.Kind() == model.KindKMSKey && r.Grants() == state
		}
	}
	var parts []string
	if list := named(inv, key(model.GrantsTerraform)); list != "" {
		parts = append(parts, "KMS grants created at runtime by AWS services are not visible in IaC: a grant can give kms:Decrypt "+
			"to a principal the key policy does not name, so a path through one of these keys can be missed: "+list)
	}
	if list := named(inv, key(model.GrantsNotCollected)); list != "" {
		parts = append(parts, "the grants of these keys were not collected (ListGrants failed, the snapshot predates it, or the key is not in the input), "+
			"so a path through one of them can be missed: "+list)
	}
	if len(parts) == 0 {
		return access.Note{}, false
	}
	return access.Note{Kind: "not-modelled", Subject: NoteKMSGrants, Detail: strings.Join(parts, "; ")}, true
}

// s3ACLNote: the buckets whose ACLs may affect access (DESIGN.md §6, S3
// ACLs): ACLs enabled, or Object Ownership not in the input. Object ACLs
// are not collected, and one can give anyone or another account read
// access to the data; each such bucket also has a gap. A bucket with ACLs
// disabled (BucketOwnerEnforced) is not named.
func s3ACLNote(inv *model.Inventory) (access.Note, bool) {
	list := named(inv, func(r *model.Resource) (string, bool) {
		return r.ARN(), r.Kind() == model.KindS3Bucket && r.S3().ACLs != model.False
	})
	if list == "" {
		return access.Note{}, false
	}
	return access.Note{
		Kind: "not-modelled", Subject: NoteS3ACLs,
		Detail: "object ACLs are not collected where ACLs are enabled or may be: an object ACL can grant read access to another account " +
			"or to everyone, so a path to one of these buckets can be missed: " + list,
	}, true
}

// organizationsNote: SCPs and RCPs are not collected. They can only
// restrict access, so without them a reported path may be one they block;
// none is hidden. Written for every scan with AWS data.
func organizationsNote(inv *model.Inventory) (access.Note, bool) {
	aws := len(inv.Principals) > 0
	for _, r := range inv.Resources {
		aws = aws || strings.HasPrefix(string(r.Kind()), "aws:")
	}
	if !aws {
		return access.Note{}, false
	}
	return access.Note{
		Kind: "not-modelled", Subject: NoteOrganizations,
		Detail: "AWS Organizations service and resource control policies are not collected; they can only restrict access, " +
			"so a reported path may be one they block, and none is hidden",
	}, true
}

// ramNote: AWS RAM shares are not collected (DESIGN.md 12.1). Only an
// advanced-tier SSM parameter can be shared, so the note names the
// parameters of the input that are, may become or may be advanced; with
// none, nothing is missed and there is no note.
func ramNote(inv *model.Inventory) (access.Note, bool) {
	list := named(inv, func(r *model.Resource) (string, bool) {
		tier := r.Tier()
		if tier == "" {
			tier = "tier unknown"
		}
		return r.ARN() + " (" + tier + ")", r.Shareable()
	})
	if list == "" {
		return access.Note{}, false
	}
	return access.Note{
		Kind: "not-modelled", Subject: NoteRAMShares,
		Detail: "cross-account access is evaluated from the resource policies collected; a share through AWS RAM is not collected, " +
			"so another account it grants read access to is not seen. Only advanced-tier parameters can be shared: " + list,
	}, true
}

// NoteUnclassified is the subject of the note that names the data stores
// no rule classifies (DESIGN.md §5, crown jewels).
const NoteUnclassified = "Unclassified data stores"

// unclassifiedNotes: the data stores that nothing classified. By default
// they are jewels of classification unclassified, and the note says how to
// classify them; with crown_jewels.unclassified: ignore they are no jewels,
// and the note says they were not scanned.
func unclassifiedNotes(inv *model.Inventory, cfg *config.Config) []access.Note {
	ignore := cfg.CrownJewels.IgnoreUnclassified()
	var count int
	list := named(inv, func(r *model.Resource) (string, bool) {
		class, _ := r.Classification()
		ok := classify.DataStore(r) && (class == classify.Unclassified || ignore && class == "")
		if ok {
			count++
		}
		return r.ARN(), ok
	})
	if count == 0 {
		return nil
	}
	stores, has := "1 data store has", "was"
	if count > 1 {
		stores, has = fmt.Sprintf("%d data stores have", count), "were"
	}
	detail := stores + " no classification; treated as `unclassified`: tag them or list them in `crown_jewels.explicit`: " + list
	if ignore {
		detail = stores + " no classification and " + has + " not scanned (`crown_jewels.unclassified: ignore`): " + list
	}
	return []access.Note{{Kind: schema.NoteUnclassified, Subject: NoteUnclassified, Detail: detail}}
}
