package cmd

import (
	"fmt"
	"os"

	ini "github.com/nanitor/goini"
	"github.com/op/go-logging"
	"xorm.io/xorm"

	"nanscraper/cmd/config"
	"nanscraper/common"
)

const (
	envKey = "NANSCRAPER_SETTINGS"
)

var (
	MainCfg *config.MainConfig
	Engine  *xorm.Engine
	log     *logging.Logger
)

func initCfg(cmdSectionName string) error {
	var err error
	MainCfg, err = loadConfig(cmdSectionName)
	if err != nil {
		return err
	}

	Engine = MainCfg.Database.MustGetEngine()

	log, err = MainCfg.Logging.Configure()
	if err != nil {
		return err
	}

	return nil
}

func loadConfig(cmdSectionName string) (*config.MainConfig, error) {
	configPath := os.Getenv(envKey)
	if configPath == "" {
		return nil, fmt.Errorf("Missing env variable: %s", envKey)
	}

	exists, err := common.PathExists(configPath)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, fmt.Errorf("Config path '%s' does not exist. May want to specify check the environment variable '%s'", configPath, envKey)
	}

	dict, err := ini.Load(configPath)
	if err != nil {
		return nil, err
	}

	return config.MainConfigFromDict(dict, cmdSectionName)
}
