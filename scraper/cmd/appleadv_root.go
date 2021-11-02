package cmd

import (
	"github.com/spf13/cobra"
)

// APPLEADVRootCMD represents the appleadv root command.
var APPLEADVRootCMD = &cobra.Command{
	Use: "appleadv commands related to apple by URL requirement",
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
		cmd.Help()
	},
}

// init function initialises the appleadv command with options.
func init() {
	rootCmd.AddCommand(APPLEADVRootCMD)
}
