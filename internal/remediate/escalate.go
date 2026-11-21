package remediate

import (
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/model"
)

// escalationActions: the IAM actions an escalation edge rests on.
func escalationActions(sub string) []string {
	switch {
	case sub == "iam:modify-policy":
		return []string{"iam:PutRolePolicy", "iam:AttachRolePolicy"}
	case sub == "iam:update-trust":
		return []string{"iam:UpdateAssumeRolePolicy"}
	case strings.HasPrefix(sub, "iam:passrole:"):
		return []string{"iam:PassRole"}
	}
	return nil
}

// escalate: an IAM escalation's identity side. A revoke removes the
// explicit grant of the action on the target role; a narrow fix denies the
// actions on it (Phase 6 review: the escalation edge itself is cuttable).
func (x *context) escalate() {
	actions := escalationActions(x.e.Sub)
	if actions == nil || x.fix.Side != "identity" {
		x.todo("no generator for %s fixes yet (%s side: %s); change it by hand", x.e.Sub, x.fix.Side, x.fix.Policy)
		return
	}
	role, src := x.to(), x.from()
	action := actions[0]
	for _, g := range x.fix.Grants {
		if s := x.statement(g); s != nil {
			acts, _ := s.Actions()
			for _, a := range actions {
				if slices.ContainsFunc(acts, func(v string) bool { return strings.EqualFold(v, a) }) {
					action = a
				}
			}
		}
	}
	t := &target{action: action, resource: role, principal: src}
	x.policySide(t, &model.StatementInput{Action: actions, Resource: []string{role}},
		"deny "+strings.Join(actions, ", ")+" on "+role+" to "+src)
}
