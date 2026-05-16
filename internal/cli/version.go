package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	buildVersion = "dev"
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

// SetBuildInfo wires ldflag-injected build metadata from main into the CLI
// package so the version command can render it.
func SetBuildInfo(version, commit, date string) {
	if version != "" {
		buildVersion = version
	}
	if commit != "" {
		buildCommit = commit
	}
	if date != "" {
		buildDate = date
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print build version, commit, and date.",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintf(cmd.OutOrStdout(), "possession %s (commit %s, built %s)\n",
			buildVersion, buildCommit, buildDate)
		return nil
	},
}
