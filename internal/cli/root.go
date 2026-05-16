// Package cli wires the cobra command tree for the possession binary.
package cli

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "possession",
	Short: "Replay authenticated HTTP requests under different identities to find authz bugs.",
	Long: `possession is a CLI auth/authz fuzzer. It ingests a HAR or curl
capture, normalizes endpoints, and (in later packets) replays each request
under every identity in a role matrix to surface IDOR, privilege
escalation, and authn bypass.

Packet 1 implements parsing, normalization, config loading, and the CLI
shell. Replay (P2), detection (P3), and reporting (P4) follow.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command. main() forwards into this.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(parseCmd, scanCmd, versionCmd)
}
