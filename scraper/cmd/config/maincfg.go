package config

import (
	"fmt"

	ini "github.com/nanitor/goini"
)

type MainConfig struct {
	DataDirectory       string
	MigrationsDirectory string
	MsrcMSUAPIKey       string
	Database            *DatabaseConfig
	Logging             *LoggingConfig
}

func MainConfigFromDict(dict ini.Dict, cmdSectionName string) (*MainConfig, error) {
	var err error

	ret := MainConfig{}
	ret.DataDirectory = dict.GetStringDef("main", "data_directory", "")
	if ret.DataDirectory == "" {
		return nil, fmt.Errorf("data_directory is empty")
	}

	ret.MigrationsDirectory = dict.GetStringDef("main", "migrations_directory", "")
	if ret.MigrationsDirectory == "" {
		return nil, fmt.Errorf("migrations_directory is empty")
	}

	ret.MsrcMSUAPIKey = dict.GetStringDef("main", "msrc_msu_api_key", "")
	if ret.MsrcMSUAPIKey == "" {
		return nil, fmt.Errorf("msrc api key is empty")
	}

	ret.Database, err = DatabaseConfigFromDict(dict)
	if err != nil {
		return nil, err
	}

	ret.Logging, err = LoggingConfigFromDict(dict, cmdSectionName)
	if err != nil {
		return nil, err
	}

	return &ret, nil
}
