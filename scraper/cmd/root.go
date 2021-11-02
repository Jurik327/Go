package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const appName = "nanscraper"
const appVersion = "0.1.0"

var rootCmd = &cobra.Command{
	Use: "nanscraper",
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
		cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
