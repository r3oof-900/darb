// Command darb is the Cross-Layer Cloud Attack-Path Analyzer.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/r3oof-900/darb/internal/cli"
)

func main() {
	os.Exit(int(run()))
}

// run is the only place that recovers panics; they map to exit code 4
// (with --debug, the stack trace is printed too).
func run() (code cli.ExitCode) {
	defer func() {
		if r := recover(); r != nil {
			cli.Crash(os.Stderr, os.Args[1:], r)
			code = cli.ExitInternal
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
}
