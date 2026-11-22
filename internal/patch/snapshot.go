package patch

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/remediate"
)

// Policies read from an offline snapshot or a live account are fixed as a
// complete JSON policy document, ready for iam:PutRolePolicy (or, when no
// statement remains, iam:DeleteRolePolicy) — never as a Terraform diff. For
// the level-2 verification the same document is written into a copy of the
// snapshot, so the rescan reads it.

// docJSON renders a policy document as IAM JSON.
func docJSON(d *model.PolicyDocument) (string, error) {
	stmts := make([]map[string]any, 0, len(d.Statements()))
	for _, s := range d.Statements() {
		stmts = append(stmts, statementMap(s))
	}
	version := d.Version()
	if version == "" {
		version = model.Version2012
	}
	b, err := json.MarshalIndent(map[string]any{"Version": version, "Statement": stmts}, "", "  ")
	return string(b), err
}

// element is the JSON name of an element or its negated form.
func element(name string, negated bool) string {
	if negated {
		return "Not" + name
	}
	return name
}

func statementMap(s *model.Statement) map[string]any {
	st := map[string]any{"Effect": s.Effect().String()}
	if s.Sid() != "" {
		st["Sid"] = s.Sid()
	}
	if spec, neg := s.Principal(); spec != nil {
		var p any = "*"
		if !spec.Wildcard() {
			byType := map[string][]string{}
			for _, r := range spec.Refs() {
				byType[string(r.Type)] = append(byType[string(r.Type)], r.Value)
			}
			p = byType
		}
		st[element("Principal", neg)] = p
	}
	acts, neg := s.Actions()
	st[element("Action", neg)] = acts
	if rs, negRes := s.Resources(); len(rs) > 0 {
		st[element("Resource", negRes)] = rs
	}
	if cs := s.Conditions(); len(cs) > 0 {
		cond := map[string]map[string][]string{}
		for i := range cs {
			c := &cs[i]
			if cond[c.Operator()] == nil {
				cond[c.Operator()] = map[string][]string{}
			}
			cond[c.Operator()][c.Key()] = c.Values()
		}
		st["Condition"] = cond
	}
	return st
}

// snapshotPolicy fixes an inline role policy of a snapshot or live account
// ("<role ARN>#inline/<name>").
func (p *patcher) snapshotPolicy(pe *policyEdits) error {
	roleARN, name, ok := strings.Cut(pe.doc.ID(), "#inline/")
	if !ok {
		return todo("%s is a managed policy of the account: create a new policy version by hand (%s)", pe.doc.ID(), p.byHand(pe))
	}
	inv := &model.Inventory{Policies: []*model.AttachedPolicy{{Doc: pe.doc}}}
	changed, err := remediate.Apply(inv, pe.edits)
	if err != nil {
		return err
	}
	doc := changed.Policies[0].Doc
	account, role := arnParts(roleARN)
	pol := Policy{ID: pe.doc.ID()}
	if len(doc.Statements()) == 0 {
		pol.Note = fmt.Sprintf("no statement remains: delete the inline policy (aws iam delete-role-policy --role-name %s --policy-name %s)", role, name)
	} else {
		if pol.Document, err = docJSON(doc); err != nil {
			return err
		}
		pol.Note = fmt.Sprintf("apply with aws iam put-role-policy --role-name %s --policy-name %s --policy-document file://policy.json", role, name)
	}
	p.res.Policies = append(p.res.Policies, pol)
	return p.writeSnapshot(account, role, name, doc)
}

// arnParts: account and role name of arn:aws:iam::<account>:role/<path/><name>.
func arnParts(arn string) (account, role string) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return "", ""
	}
	return parts[4], parts[5][strings.LastIndex(parts[5], "/")+1:]
}

// writeSnapshot writes the changed inline policy into the snapshot copy's
// get-account-authorization-details.json (removing it when empty).
func (p *patcher) writeSnapshot(account, role, name string, doc *model.PolicyDocument) error {
	for _, dir := range p.opts.Snapshots {
		file := path.Join(dir, account, "iam", "get-account-authorization-details.json")
		data, err := p.src.Read(file)
		if err != nil {
			continue
		}
		var root map[string]any
		if jerr := json.Unmarshal(data, &root); jerr != nil {
			return fmt.Errorf("patch: %s: %w", file, jerr)
		}
		found, err := setInlinePolicy(root, role, name, doc)
		if err != nil || !found {
			if err != nil {
				return err
			}
			continue
		}
		out, err := json.Marshal(root)
		if err != nil {
			return err
		}
		p.res.Snapshot = append(p.res.Snapshot, FileChange{Path: file, Before: data, After: append(out, 10)})
		return nil
	}
	return todo("the inline policy %s of role %s is not in a snapshot of this input: apply the policy document in the account", name, role)
}

// setInlinePolicy replaces (or, with no statement left, removes) the inline
// policy name of role in an authorization-details document.
func setInlinePolicy(root map[string]any, role, name string, doc *model.PolicyDocument) (bool, error) {
	roles, _ := root["RoleDetailList"].([]any)
	for _, r := range roles {
		rd, _ := r.(map[string]any)
		if rd["RoleName"] != role {
			continue
		}
		list, _ := rd["RolePolicyList"].([]any)
		for i, ip := range list {
			pd, _ := ip.(map[string]any)
			if pd["PolicyName"] != name {
				continue
			}
			if len(doc.Statements()) == 0 {
				rd["RolePolicyList"] = append(list[:i:i], list[i+1:]...)
				return true, nil
			}
			js, err := docJSON(doc)
			if err != nil {
				return false, err
			}
			var v any = js // a document stored as a JSON string stays one
			if _, isString := pd["PolicyDocument"].(string); !isString {
				_ = json.Unmarshal([]byte(js), &v)
			}
			pd["PolicyDocument"] = v
			return true, nil
		}
	}
	return false, nil
}
