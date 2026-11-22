package patch

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	udiff "github.com/aymanbagabas/go-udiff"

	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/remediate"
)

// Source reads the scan's files; paths are slash-separated and relative to
// the scan root.
type Source interface {
	Read(path string) ([]byte, error)
	// List returns the files directly in dir (as paths from the root).
	List(dir string) ([]string, error)
	// Walk returns every file under dir, recursively.
	Walk(dir string) ([]string, error)
}

// Options locate inputs the edits do not name.
type Options struct {
	Snapshots []string // offline snapshot directories
	// ConfigDirs are the Terraform configurations (scanned directories and
	// the directories plans were made from): where a resource read from a
	// plan is defined.
	ConfigDirs []string
}

// FileChange is one edited file.
type FileChange struct {
	Path          string
	Before, After []byte
}

// Policy is a complete policy document for a policy of a snapshot or a live
// account, with how to apply it.
type Policy struct {
	ID       string
	Document string // IAM JSON; empty when the policy is to be deleted
	Note     string
}

// Result is a rendered patch.
type Result struct {
	Files    []FileChange // Terraform and Kubernetes files of the input
	Policies []Policy     // snapshot or live policies, as JSON
	// Snapshot: the snapshot files written for the level-2 rescan (not part
	// of the patch a user applies).
	Snapshot []FileChange
	// TODO: edits that could not be placed exactly, with why and what to do.
	TODO []string
}

// Complete reports whether every edit was rendered.
func (r *Result) Complete() bool { return len(r.TODO) == 0 }

// Diff is the unified diff of the edited input files.
func (r *Result) Diff() string {
	var b strings.Builder
	for _, f := range r.Files {
		b.WriteString(udiff.Unified("a/"+f.Path, "b/"+f.Path, string(f.Before), string(f.After)))
	}
	return b.String()
}

type patcher struct {
	src   Source
	opts  *Options
	refs  *refs
	files map[string]*text
	tfs   map[string]*tfFile
	order []string
	res   *Result
}

// text returns the file being edited (read once).
func (p *patcher) text(file string) (*text, error) {
	if t, ok := p.files[file]; ok {
		return t, nil
	}
	data, err := p.src.Read(file)
	if err != nil {
		return nil, fmt.Errorf("patch: %w", err)
	}
	t := newText(file, data)
	p.files[file] = t
	p.order = append(p.order, file)
	return t, nil
}

// tf returns a Terraform file being edited, parsed.
func (p *patcher) tf(file string) (*tfFile, error) {
	if f, ok := p.tfs[file]; ok {
		return f, nil
	}
	if !strings.HasSuffix(file, ".tf") {
		return nil, fmt.Errorf("patch: %s is not a Terraform file", file)
	}
	data, err := p.src.Read(file)
	if err != nil {
		return nil, fmt.Errorf("patch: %w", err)
	}
	f, err := parseTF(file, data)
	if err != nil {
		return nil, err
	}
	if t, ok := p.files[file]; ok {
		f.text = t
	} else {
		p.files[file] = f.text
		p.order = append(p.order, file)
	}
	p.tfs[file] = f
	return f, nil
}

// Render places the edits in the input files. An edit that cannot be placed
// exactly is a TODO; an internal inconsistency is an error. Every edited
// file is parsed again before it is returned.
func Render(inv *model.Inventory, edits []remediate.Edit, src Source, opts *Options) (*Result, error) {
	if opts == nil {
		opts = &Options{}
	}
	p := &patcher{src: src, opts: opts, refs: newRefs(inv), files: map[string]*text{}, tfs: map[string]*tfFile{}, res: &Result{}}
	docs, err := p.placeAll(inv, edits)
	if err != nil {
		return nil, err
	}
	for _, pe := range docs {
		place := p.snapshotPolicy
		if terraformDoc(pe.doc) {
			place = p.tfPolicy
		}
		if err := p.keep(place(pe)); err != nil {
			return nil, err
		}
	}
	if err := p.finish(); err != nil {
		return nil, err
	}
	return p.res, nil
}

// placeAll places the edits that are not policy edits and groups the
// policy edits by document, in order.
func (p *patcher) placeAll(inv *model.Inventory, edits []remediate.Edit) ([]*policyEdits, error) {
	var docs []*policyEdits
	byDoc := map[string]*policyEdits{}
	for i := range edits {
		e := &edits[i]
		var err error
		switch e.Op {
		case remediate.OpAddStatement, remediate.OpRemoveValues, remediate.OpRemoveStatement, remediate.OpSetValues:
			pe, ok := byDoc[e.Policy]
			if !ok {
				doc := remediate.Document(inv, e.Policy)
				if doc == nil {
					return nil, fmt.Errorf("patch: policy %s is not in the inventory", e.Policy)
				}
				pe = &policyEdits{doc: doc}
				byDoc[e.Policy] = pe
				docs = append(docs, pe)
			}
			pe.edits = append(pe.edits, *e)
		case remediate.OpNodeMetadata:
			err = p.nodeMetadata(e)
		case remediate.OpRemoveHostNetwork:
			err = p.removeHostNetwork(e)
		case remediate.OpDisableTokenMount:
			err = p.disableTokenMount(e)
		case remediate.OpRemoveSecretRef:
			err = p.removeSecretRef(e)
		case remediate.OpRemoveExposure:
			err = p.removeExposure(e)
		case remediate.OpRestrictPublic:
			err = p.restrictPublic(e)
		case remediate.OpDetachPolicy:
			err = p.detachPolicy(e)
		}
		if kept := p.keep(err); kept != nil {
			return nil, kept
		}
	}
	return docs, nil
}

// finish applies each file's splices and parses the result again.
func (p *patcher) finish() error {
	for _, file := range p.order {
		t := p.files[file]
		if len(t.splices) == 0 {
			continue
		}
		after, err := t.result()
		if err != nil {
			return err
		}
		if verr := valid(file, after); verr != nil {
			return verr
		}
		before, _ := p.src.Read(file)
		p.res.Files = append(p.res.Files, FileChange{Path: file, Before: before, After: after})
	}
	slices.SortFunc(p.res.Files, func(a, b FileChange) int { return strings.Compare(a.Path, b.Path) })
	return nil
}

// terraformDoc: a policy of a Terraform resource (from a configuration or a
// plan), not of a snapshot or live account (whose IDs are ARNs).
func terraformDoc(d *model.PolicyDocument) bool {
	return d.Source().Address() != "" && !strings.HasPrefix(d.ID(), "arn:")
}

// keep records a TODO and passes other errors on.
func (p *patcher) keep(err error) error {
	if errors.Is(err, errTODO) {
		p.res.TODO = append(p.res.TODO, strings.TrimPrefix(err.Error(), errTODO.Error()+": "))
		return nil
	}
	return err
}

// valid parses an edited file again (DESIGN.md §9.3).
func valid(file string, data []byte) error {
	switch {
	case strings.HasSuffix(file, ".tf"):
		return validTF(file, data)
	case strings.HasSuffix(file, ".yaml"), strings.HasSuffix(file, ".yml"):
		return validYAML(data)
	}
	return nil
}
