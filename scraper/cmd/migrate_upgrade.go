/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.md', which is part of this source code package.
 */

package cmd

import (
	"fmt"
	"os"
	"strings"

	_ "github.com/lib/pq"
	"github.com/spf13/cobra"

	"nanscraper/cmd/migrations"
	"nanscraper/common"
)

const cliCfgSection = "cli"

var migrateUpgradeCmd = &cobra.Command{
	Use:                   "migrate_upgrade",
	Short:                 "Migrate upgrade",
	Long:                  "",
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		err := initCfg(cliCfgSection)
		if err != nil {
			fmt.Printf("Failed to init config: %v\n", err)
			os.Exit(1)
		}

		if len(args) == 0 {
			log.Info("Please specify version to upgrade to, either a specific version or head for latest available")
			return
		}

		requested := strings.ToLower(args[0])
		pretend, err := cmd.Flags().GetBool("development")
		if err != nil {
			pretend = false
		}

		if pretend {
			log.Info("Pretend mode enabled, just printing what would be applied")
		}

		session, err := common.StartDBSession(Engine)
		if err != nil {
			fmt.Printf("Failed to open DB: %v\n", err)
			os.Exit(1)
		}

		defer common.CleanupDBSession(session)

		mm := migrations.MigrationManager{}
		mm.Directory = MainCfg.MigrationsDirectory
		mm.Session = session

		err = migrations.MigrateUpgrade(&mm, requested, pretend)
		if err != nil {
			fmt.Printf("Failed to run DB Migrate upgrade: %s\n", err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(migrateUpgradeCmd)

	migrateUpgradeCmd.Flags().BoolP("pretend", "p", false, "Pretend mode")
}
