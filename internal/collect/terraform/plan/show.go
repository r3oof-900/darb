package plan

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/r3oof-900/clapa/internal/collect"
)

// showTimeout bounds "terraform show -json".
const showTimeout = 2 * time.Minute

// showJSON converts a binary plan file with "terraform show -json <file>".
// This is the only os/exec in CLAPA (docs/DESIGN.md section 4.1): an
// argument slice, no shell, a timeout, a stdout size cap, and a binary
// resolved by exec.LookPath (which refuses results relative to the current
// directory) or given explicitly.
func showJSON(ctx context.Context, in *collect.Input, opts *Options) ([]byte, error) {
	bin := opts.TerraformBin
	if bin == "" {
		found, err := exec.LookPath("terraform")
		if err != nil {
			return nil, fmt.Errorf("%w: %s looks like a binary plan file and no terraform binary was found (%w); pass plan JSON from \"terraform show -json\"",
				ErrNotJSON, in.Path, err)
		}
		bin = found
	}
	ctx, cancel := context.WithTimeout(ctx, showTimeout)
	defer cancel()
	planPath := filepath.Join(in.Root, filepath.FromSlash(in.Path))
	cmd := exec.CommandContext(ctx, bin, "show", "-json", "-no-color", planPath) //nolint:gosec // G204: fixed arguments, binary chosen by the user or LookPath; no shell.
	cmd.Dir = filepath.Dir(planPath)
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1")
	out := &capped{max: in.Limits.MaxFileBytes}
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = out, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: terraform show -json %s: %w: %s", Name, in.Path, err, bytes.TrimSpace(stderr.Bytes()))
	}
	if out.overflow {
		return nil, fmt.Errorf("%s: terraform show output exceeds %d bytes", Name, in.Limits.MaxFileBytes)
	}
	return out.buf.Bytes(), nil
}

// capped is a writer that keeps at most max bytes.
type capped struct {
	buf      bytes.Buffer
	max      int64
	overflow bool
}

func (c *capped) Write(p []byte) (int, error) {
	room := c.max - int64(c.buf.Len())
	if int64(len(p)) > room {
		c.overflow = true
		c.buf.Write(p[:max(room, 0)])
		return len(p), nil
	}
	return c.buf.Write(p)
}
