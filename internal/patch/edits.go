package patch

import (
	"fmt"
	"slices"

	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/remediate"
)

// stmtList is the statements of one policy in one of the forms a patch
// edits (jsonencode, a JSON heredoc, a policy document data source).
type stmtList interface {
	count() int
	// render writes a new statement in the form.
	render(s *model.StatementInput) (string, error)
	// removeValues removes an edit's values from statement i; true when
	// nothing is left of the element (the statement goes).
	removeValues(i int, e *remediate.Edit) (bool, error)
	// commit removes the statements and appends the new ones.
	commit(removed map[int]bool, added []string) error
}

// editPolicy applies the edits of one policy to its statements; empty runs
// when no statement would remain.
func editPolicy(l stmtList, edits []remediate.Edit, id string, empty func() error) error {
	removed := map[int]bool{}
	var added []string
	for i := range edits {
		gone, s, err := editOne(l, &edits[i], id)
		if err != nil {
			return err
		}
		if s != "" {
			added = append(added, s)
		}
		if gone {
			removed[edits[i].Index] = true
		}
	}
	if l.count() > 0 && len(removed) == l.count() && len(added) == 0 {
		return empty()
	}
	return l.commit(removed, added)
}

func editOne(l stmtList, e *remediate.Edit, id string) (gone bool, added string, err error) {
	switch e.Op {
	case remediate.OpAddStatement:
		s, err := l.render(e.Statement)
		if err != nil {
			return false, "", todo("%s", err.Error())
		}
		return false, s, nil
	case remediate.OpRemoveStatement, remediate.OpRemoveValues:
		if e.Index < 0 || e.Index >= l.count() {
			return false, "", fmt.Errorf("patch: %s has no statement %d", id, e.Index)
		}
		if e.Op == remediate.OpRemoveStatement {
			return true, "", nil
		}
		gone, err := l.removeValues(e.Index, e)
		return gone, "", err
	case remediate.OpNodeMetadata, remediate.OpRemoveHostNetwork, remediate.OpRemoveExposure, remediate.OpRestrictPublic:
	}
	return false, "", nil
}

// evaluator evaluates value i of a list: its string, or false and why.
type evaluator func(i int) (string, bool, string)

// drops returns the indices of the n values whose value an edit removes; a
// value the input does not fix is a TODO (with the place to change it).
func (c *pctx) drops(n int, eval evaluator, e *remediate.Edit, key string) ([]int, error) {
	var drop []int
	for i := range n {
		s, ok, why := eval(i)
		if !ok {
			return nil, todo("%s of statement %d of %s: %s; %s", key, e.Index, c.doc.ID(), why, c.p.inputHint(c.f, c.mod, why))
		}
		if slices.Contains(e.Values, s) {
			drop = append(drop, i)
		}
	}
	return drop, nil
}

// matching is drops for one list: one value at least must match, and an
// instance of count or for_each is not edited (the change would apply to
// every instance).
func (c *pctx) matching(n int, eval evaluator, e *remediate.Edit, key string) ([]int, error) {
	drop, err := c.drops(n, eval, e, key)
	switch {
	case err != nil:
		return nil, err
	case len(drop) == 0:
		return nil, fmt.Errorf("patch: %s statement %d: none of %v is in its %s", c.doc.ID(), e.Index, e.Values, key)
	case c.indexed:
		return nil, todo("%s is an instance of a resource with count or for_each: removing %v there removes it from every instance", c.doc.ID(), e.Values)
	}
	return drop, nil
}
