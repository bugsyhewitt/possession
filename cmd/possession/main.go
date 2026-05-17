// Command possession is a CLI auth/authz fuzzer that replays known-good
// authenticated HTTP requests under different identities and reports
// authz bypasses.
//
// Packet 1 ships parsing, normalization, config loading, and CLI scaffolding.
// Replay, detection, and reporting land in Packets 2–4.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/bugsyhewitt/possession/internal/cli"
)

// Build-time variables, populated via `go build -ldflags "-X ..."`.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	cli.SetBuildInfo(version, commit, date)
	if err := cli.Execute(); err != nil {
		var ee *cli.ExitError
		if errors.As(err, &ee) {
			// Typed exit codes from cli (e.g. exit 3 when scan reports
			// findings). Message is informational, not an error.
			fmt.Fprintln(os.Stderr, ee.Msg)
			os.Exit(ee.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
