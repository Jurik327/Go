package cmd

import (
	"fmt"
	"nanscraper/common"
	"nanscraper/pkg/feeders"
	"nanscraper/pkg/models/pqmodels"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var feedsIndexCmd = &cobra.Command{
	Use:   "index indexes data for given feed",
	Short: "index most recent feed data to database",
	Long: `
The feeds index command indexes the most recent feed data from disk
and adds to the psql database.
`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Printf("Ned to specify the feed name to index\n")
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

		fmt.Printf("Indexing for %s\n", fname)
		err = feeder.Index(Engine, MainCfg.DataDirectory)
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
			log.Errorf("No record of %v - please download first", fname)
			return
		} else {
			// Update last indexed at.
			feed.LastIndexedAt = &utcNow
			_, err = session.Where(`id = ?`, feed.Id).
				Cols("last_indexed_at").
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

		fmt.Printf("Indexing complete and DB updated\n")
	},
}

func init() {
	feedsRootcmd.AddCommand(feedsIndexCmd)
}
