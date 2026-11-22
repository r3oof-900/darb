package patch

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/r3oof-900/darb/internal/model"
)

// refs maps the ARNs (and S3 bucket names) of the resources and principals
// the input defines in Terraform to their addresses, so a fix references
// them (aws_kms_key.pii.arn) instead of writing an ARN: Terraform-defined
// key ARNs are not even known before apply. An ARN is referenced only from a
// file of the same directory and module as its definition.
type refs struct {
	byARN  map[string]ref // ARN -> definition
	byAddr map[string]ref // dir|address -> definition
}

type ref struct {
	dir, addr, arn, name string
}

// moduleOf splits "module.a.module.b.aws_x.y[\"k\"]" into its module path
// and the address within the module.
func moduleOf(address string) (module, local string) {
	parts := strings.Split(address, ".")
	i := 0
	for i+1 < len(parts) && parts[i] == "module" {
		i += 2
	}
	return strings.Join(parts[:i], "."), strings.Join(parts[i:], ".")
}

func newRefs(inv *model.Inventory) *refs {
	r := &refs{byARN: map[string]ref{}, byAddr: map[string]ref{}}
	add := func(arn string, src *model.SourceLocation, name string) {
		if src.Address() == "" || strings.HasPrefix(src.Address(), "arn:") || !strings.HasSuffix(src.File(), ".tf") && !strings.HasSuffix(src.File(), ".json") {
			return
		}
		dir := path.Dir(src.File())
		if !strings.HasSuffix(src.File(), ".tf") {
			dir = "" // from a plan: matched by module and address only
		}
		x := ref{dir: dir, addr: src.Address(), arn: arn, name: name}
		r.byARN[arn] = x
		r.byAddr[x.dir+"|"+x.addr] = x
	}
	for _, p := range inv.Principals {
		add(p.Identity(), p.Source(), "")
	}
	for _, res := range inv.Resources {
		name := ""
		if res.Kind() == model.KindS3Bucket {
			name = strings.TrimPrefix(res.ARN(), "arn:aws:s3:::")
		}
		add(res.ARN(), res.Source(), name)
	}
	return r
}

// local: the reference to x from a file in dir and module mod ("" when x is
// defined elsewhere).
func (r *refs) local(x ref, dir, mod string) string {
	xm, xl := moduleOf(x.addr)
	if x.dir != "" && x.dir != dir || xm != mod {
		return ""
	}
	return xl
}

// value is one string of a policy as a patch writes it.
type value struct {
	ref    string // a Terraform reference ("aws_kms_key.pii.arn")
	suffix string // text after the reference ("/*")
	lit    string // a literal, when ref is empty
}

// synthetic: an ARN the normalizer made up for a value Terraform knows only
// after apply; a patch must not write it.
var synthetic = regexp.MustCompile(`:key/tf-|-tfpend$|^arn:darb:`)

// resolve renders an ARN for a file: a reference to its definition in the
// same module, the reference plus a suffix for "<ARN>/<objects>", or the ARN
// itself when it is a real one from the input.
func (r *refs) resolve(arn, dir, mod string) (value, error) {
	if x, ok := r.byARN[arn]; ok {
		if l := r.local(x, dir, mod); l != "" {
			return value{ref: l + ".arn"}, nil
		}
	}
	if i := strings.Index(arn, "/"); strings.HasPrefix(arn, "arn:aws:s3:::") && i > 0 {
		if x, ok := r.byARN[arn[:i]]; ok {
			if l := r.local(x, dir, mod); l != "" {
				return value{ref: l + ".arn", suffix: arn[i:]}, nil
			}
		}
	}
	if synthetic.MatchString(arn) || model.ContainsUnresolved(arn) {
		return value{}, fmt.Errorf("%s is known only after apply and is not defined in this module: write the reference by hand", arn)
	}
	return value{lit: arn}, nil
}

// lookup resolves a reference ("aws_s3_bucket.b.arn", ".id", ".bucket",
// ".name") made in dir to the value the input gives it.
func (r *refs) lookup(traversal, dir, mod string) (string, bool) {
	i := strings.LastIndex(traversal, ".")
	if i < 0 {
		return "", false
	}
	addr, attr := traversal[:i], traversal[i+1:]
	if mod != "" {
		addr = mod + "." + addr
	}
	x, ok := r.byAddr[dir+"|"+addr]
	if !ok {
		if x, ok = r.byAddr["|"+addr]; !ok {
			return "", false
		}
	}
	switch attr {
	case "arn":
		return x.arn, true
	case "id", "bucket":
		return x.name, x.name != ""
	case "name":
		if x.name != "" {
			return x.name, true
		}
		return x.arn[strings.LastIndex(x.arn, "/")+1:], true
	}
	return "", false
}
