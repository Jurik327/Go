package cmd

import (
	"github.com/spf13/cobra"
)

// feedsRootcmd represents the feeds command.
var feedsRootcmd = &cobra.Command{
	Use: "feeds commands related to listting, downloading and indexing feeds",
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
		cmd.Help()
	},
}

// init function initialises the scrape command with options.
func init() {
	rootCmd.AddCommand(feedsRootcmd)
}
