package cmd

import (
	"fmt"
	"nanscraper/pkg/appleadv"
	"os"

	"github.com/spf13/cobra"
)

var APPLEADVLookupCMD = &cobra.Command{
	Use:   "lookup gets advisory by URL",
	Short: "lookup gets advisory by URL",
	Long:  `The APPLEADV command to search advisories or help by URL`,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) < 1 {
			fmt.Println("Need to specify Apple Security URL")
			os.Exit(1)
		}
		result, err := appleadv.Lookup(args[0])

		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		fmt.Println(result.HTML)
	},
}

func init() {
	APPLEADVRootCMD.AddCommand(APPLEADVLookupCMD)
}
