package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"nanscraper/common"
	"nanscraper/pkg/feeders"
	"nanscraper/pkg/models/pqmodels"
	"os"
	"time"
)

var feedsDownloadCmd = &cobra.Command{
	Use:   "download downloads data for given feed",
	Short: "download and update feed data",
	Long: `
The feeds download command downloads and updates the data for the
specified feed.
`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Printf("Ned to specify the feed name to download updates for\n")
			os.Exit(1)
		}
		fname := args[0]
		err := initCfg(cliCfgSection)
		if err != nil {
			fmt.Printf("Failed to init config: %v\n", err)
			os.Exit(1)
		}
		initFeeds()

		var feeder feeders.Feeder
		for _, f := range feedSources {
			if f.Name() == fname {
				feeder = f
			}
		}
		if feeder == nil {
			fmt.Printf("Feed %s not registered\n", fname)
			os.Exit(1)
		}

		fmt.Printf("Downloading for %s\n", fname)
		err = feeder.Download(Engine, MainCfg.DataDirectory)
		if err != nil {
			panic(err)
		}

		// Update feed DB record.
		session, err := common.StartDBSession(Engine)
		if err != nil {
			log.Errorf("[%s] ERROR: %v", feeder.Name(), err)
			return
		}

		defer common.CleanupDBSession(session)
		var feed pqmodels.Feed
		has, err := session.Where(`name = ?`, feeder.Name()).Get(&feed)
		if err != nil {
			log.Errorf("[%s] DB Error: %v", feeder.Name(), err)
			return
		}
		utcNow := time.Now().UTC()
		if !has {
			feed = pqmodels.Feed{
				Name:             feeder.Name(),
				Description:      feeder.Description(),
				LastDownloadedAt: &utcNow,
			}
			_, err = session.Insert(feed)
			if err != nil {
				log.Errorf("DB ERROR: %v", err)
				return
			}
		} else {
			// Update last indexed at.
			feed.LastDownloadedAt = &utcNow
			_, err = session.Where(`id = ?`, feed.Id).
				Cols("last_downloaded_at").
				Update(feed)
			if err != nil {
				log.Errorf("DB ERROR: %v", err)
				return
			}
		}

		err = session.Commit()
		if err != nil {
			log.Errorf("DB error: %v", err)
			return
		}

		fmt.Printf("Download complete and DB updated\n")
	},
}

func init() {
	feedsRootcmd.AddCommand(feedsDownloadCmd)
}
