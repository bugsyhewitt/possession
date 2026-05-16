package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// scanCmd is a Packet 1 stub. Packet 2 wires the replay engine; Packet 3
// wires detection; Packet 4 wires reporting. Registering no flags keeps
// future flag additions visible in a diff rather than buried in churn.
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run an authz scan against a target (Packet 2+).",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(cmd.ErrOrStderr(), "scan: not implemented (Packet 2)")
		// Returning a sentinel error gives us a non-zero exit code without
		// cobra re-printing the message (SilenceErrors=true on root).
		return errors.New("scan not implemented")
	},
}
