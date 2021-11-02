package cmd

import (
	"fmt"
	"nanscraper/pkg/feeders/appleadv"
	"os"

	"github.com/spf13/cobra"
)

// appleadvDownloadCmd represents the Apple security updates download command.
// It should fetch all Apple security updates information
// and place in the datastore.
var appleadvDownloadCmd = &cobra.Command{
	Use:   "download downloads the newest Apple security updates data if there are updates",
	Short: "Download Apple security updates announcements",
	Long: `
The appleadv download command connects to the Apple security updates
and fetches a list of updates and stores all the documents links to
the database where it can then be processed.
`,
	RunE: func(cmd *cobra.Command, args []string) (runError error) {
		err := initCfg(cliCfgSection)
		if err != nil {
			fmt.Printf("Failed to init config: %v\n", err)
			os.Exit(1)
		}

		dirinfo, err := os.Stat(MainCfg.DataDirectory)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			os.Exit(1)
		}
		if !dirinfo.IsDir() {
			fmt.Printf("ERROR: %s should be a directory\n", MainCfg.DataDirectory)
			os.Exit(1)
		}

		appleadvfeed := appleadv.New()

		// Download data.
		err = appleadvfeed.Index(nil, MainCfg.DataDirectory)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Complete")
		return nil
	},
}

// init function initialises the scrape command with options.
func init() {
	APPLEADVRootCMD.AddCommand(appleadvDownloadCmd)
}
