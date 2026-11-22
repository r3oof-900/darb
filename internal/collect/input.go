package collect

import (
	"context"

	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/safeio"
)

// Input names what a collector reads: a file or directory (Path, relative to
// Root, slash-separated; "" or "." for Root itself).
type Input struct {
	Root   string
	Path   string
	Limits safeio.Limits
}

// Collector is the shape every collector has. T is the collector's raw type
// (tfraw.Module, k8sraw.Objects, awsraw.Snapshot); this package does not
// know it, which keeps the dependency direction collect → raw types only.
type Collector[T any] interface {
	Name() string
	Collect(ctx context.Context, in *Input, rec *coverage.Recorder) (T, error)
}
