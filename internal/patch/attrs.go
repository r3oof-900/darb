package patch

import (
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/r3oof-900/darb/internal/remediate"
)

// setAttrs sets attributes of a block: an existing attribute's value is
// replaced, a missing one is added before the closing brace, aligned with
// the block's other attributes.
func setAttrs(f *tfFile, b *hclsyntax.Block, vals [][2]string) error {
	var missing [][2]string
	for _, kv := range vals {
		if a := b.Body.Attributes[kv[0]]; a != nil {
			r := a.Expr.Range()
			f.replace(r.Start.Byte, r.End.Byte, kv[1])
		} else {
			missing = append(missing, kv)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if !f.onlySpaceBefore(b.CloseBraceRange.Start.Byte) {
		return todo("%s closes on a line with other text", b.Type)
	}
	indent := f.indentAt(b.TypeRange.Start.Byte) + "  "
	for _, a := range b.Body.Attributes {
		indent = f.indentAt(a.SrcRange.Start.Byte)
		break
	}
	var lines []string
	for _, kv := range missing {
		lines = append(lines, indent+kv[0]+" = "+kv[1])
	}
	at := f.lineStart(b.CloseBraceRange.Start.Byte)
	f.replace(at, at, strings.Join(lines, f.newline())+f.newline())
	return nil
}

// nodeMetadata sets a node group's instance metadata options in the launch
// template it uses (aws_launch_template.metadata_options).
func (p *patcher) nodeMetadata(e *remediate.Edit) error {
	ng := e.NodeGroup
	src := ng.Source
	mod, local := moduleOf(src.Address())
	typ, name, indexed, ok := resourceAddr(local)
	if !ok || indexed || !strings.HasSuffix(src.File(), ".tf") {
		return todo("node group %s is not a Terraform resource of this input: set its metadata options by hand", ng.Name)
	}
	f, err := p.tf(src.File())
	if err != nil {
		return err
	}
	b := f.block("resource", typ, name)
	var lt *hclsyntax.Block
	for _, blk := range b.Body.Blocks {
		if blk.Type == "launch_template" {
			lt = blk
		}
	}
	if lt == nil {
		return todo("node group %s has no launch template; add one with metadata_options (%s)", ng.Name, metadataText(e))
	}
	ref := ""
	for _, attr := range []string{"id", "name"} {
		if a := lt.Body.Attributes[attr]; a != nil && ref == "" {
			ref = f.srcOf(a.Expr.Range())
		}
	}
	tname, ok := strings.CutPrefix(ref, "aws_launch_template.")
	if !ok || mod != "" {
		return todo("the launch template of node group %s is %s: set its metadata_options by hand (%s)", ng.Name, ref, metadataText(e))
	}
	return p.launchTemplate(f.dir, strings.TrimSuffix(strings.TrimSuffix(tname, ".id"), ".name"), e)
}

// launchTemplate sets the metadata options of aws_launch_template.<name>.
func (p *patcher) launchTemplate(dir, name string, e *remediate.Edit) error {
	files, _ := p.src.List(dir)
	for _, file := range files {
		tf, err := p.tf(file)
		if err != nil {
			continue
		}
		t := tf.block("resource", "aws_launch_template", name)
		if t == nil {
			continue
		}
		for _, mo := range t.Body.Blocks {
			if mo.Type == "metadata_options" {
				return setAttrs(tf, mo, metadataAttrs(e))
			}
		}
		return todo("aws_launch_template.%s has no metadata_options block; add one (%s)", name, metadataText(e))
	}
	return todo("aws_launch_template.%s is not in %s", name, dir)
}

func metadataAttrs(e *remediate.Edit) [][2]string {
	if e.Endpoint != "" {
		return [][2]string{{"http_endpoint", hclString(e.Endpoint)}}
	}
	return [][2]string{{"http_tokens", hclString(e.Tokens)}, {"http_put_response_hop_limit", strconv.Itoa(e.HopLimit)}}
}

func metadataText(e *remediate.Edit) string {
	var parts []string
	for _, kv := range metadataAttrs(e) {
		parts = append(parts, kv[0]+" = "+kv[1])
	}
	return strings.Join(parts, ", ")
}

// restrictPublic sets restrict_public_buckets = true on the bucket's
// aws_s3_bucket_public_access_block.
func (p *patcher) restrictPublic(e *remediate.Edit) error {
	bucket := e.Bucket
	src := bucket.Source()
	if !strings.HasSuffix(src.File(), ".tf") {
		return todo("bucket %s is not defined in Terraform: turn on RestrictPublicBuckets (s3:PutPublicAccessBlock) by hand", bucket.ARN())
	}
	mod, _ := moduleOf(src.Address())
	name := strings.TrimPrefix(bucket.ARN(), "arn:aws:s3:::")
	files, _ := p.src.List(dirOf(src.File()))
	for _, file := range files {
		f, err := p.tf(file)
		if err != nil {
			continue
		}
		for _, b := range f.body.Blocks {
			if b.Type != "resource" || len(b.Labels) != 2 || b.Labels[0] != "aws_s3_bucket_public_access_block" {
				continue
			}
			a := b.Body.Attributes["bucket"]
			if a == nil {
				continue
			}
			c := &pctx{p: p, f: f, mod: mod}
			if v, ok, _ := c.eval(a.Expr); ok && (v == name || v == bucket.ARN()) {
				return setAttrs(f, b, [][2]string{{"restrict_public_buckets", "true"}})
			}
		}
	}
	return todo("bucket %s has no aws_s3_bucket_public_access_block in this input: add one with restrict_public_buckets = true", bucket.ARN())
}

func dirOf(file string) string {
	if i := strings.LastIndex(file, "/"); i >= 0 {
		return file[:i]
	}
	return "."
}
