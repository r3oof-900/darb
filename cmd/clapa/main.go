// Command clapa is the Cross-Layer Cloud Attack-Path Analyzer.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/r3oof-900/clapa/internal/cli"
)

func main() {
	os.Exit(int(run()))
}

// run is the only place that recovers panics; they map to exit code 4.
func run() (code cli.ExitCode) {
	defer func() {
		if r := recover(); r != nil {
			_, _ = fmt.Fprintf(os.Stderr, "clapa: internal error: %v (re-run with --debug for a stack trace)\n", r)
			code = cli.ExitInternal
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
}
