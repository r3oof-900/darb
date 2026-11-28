package app

import (
	"slices"
	"strings"
	"time"

	"github.com/r3oof-900/darb/internal/access"
	"github.com/r3oof-900/darb/internal/model"
)

// NoteTimeConditions is the subject of the note that names the policies
// whose conditions compare the request time (DESIGN.md §6.2).
const NoteTimeConditions = "Time conditions"

// timeNote: aws:CurrentTime and aws:EpochTime are decided at the scan time,
// in favour of nobody; the note names the policies that compare them, since
// a scan at another time may decide them differently. With no scan time
// they stay unknown (each decision then names them).
func timeNote(inv *model.Inventory, now time.Time) []access.Note {
	var ids []string
	add := func(d *model.PolicyDocument) {
		if d != nil && comparesTime(d) && !slices.Contains(ids, d.ID()) {
			ids = append(ids, d.ID())
		}
	}
	for _, p := range slices.Concat(inv.Policies, inv.Boundaries) {
		add(p.Doc)
	}
	for _, t := range inv.Trusts {
		add(t.Policy())
	}
	if len(ids) == 0 {
		return nil
	}
	slices.Sort(ids)
	detail := "conditions on aws:CurrentTime or aws:EpochTime were evaluated at the scan time; a scan at another time may decide them differently: "
	if now.IsZero() {
		detail = "conditions on aws:CurrentTime or aws:EpochTime are unknown: no scan time was given: "
	}
	return []access.Note{{Kind: "scan-time", Subject: NoteTimeConditions, Detail: detail + strings.Join(ids, ", ")}}
}

func comparesTime(d *model.PolicyDocument) bool {
	for _, s := range d.Statements() {
		for _, c := range s.Conditions() {
			if k := strings.ToLower(c.Key()); k == "aws:currenttime" || k == "aws:epochtime" {
				return true
			}
		}
	}
	return false
}
