package config

import (
	"fmt"
	"strings"
	"time"

	"xorm.io/xorm"
	"xorm.io/xorm/log"

	ini "github.com/nanitor/goini"
)

type DatabaseConfig struct {
	Host      string
	Port      int
	Name      string
	User      string
	Password  string
	ShowError bool
	ShowSql   bool
	ShowDebug bool
}

func DatabaseConfigFromDict(dict ini.Dict) (*DatabaseConfig, error) {
	ret := DatabaseConfig{}
	ret.Host = dict.GetStringDef("database", "host", "")
	if ret.Host == "" {
		ret.Host = "localhost"
	}
	ret.Port = dict.GetIntDef("database", "port", 5432)

	ret.Name = dict.GetStringDef("database", "name", "")
	if ret.Name == "" {
		return nil, fmt.Errorf("Missing database name")
	}

	ret.User = dict.GetStringDef("database", "user", "")
	ret.Password = dict.GetStringDef("database", "password", "")
	ret.ShowError = dict.GetBoolDef("database", "show_error", false)
	ret.ShowSql = dict.GetBoolDef("database", "show_sql", false)
	ret.ShowDebug = dict.GetBoolDef("database", "debug", false)
	return &ret, nil
}

func (this *DatabaseConfig) ConnString() string {
	options := []string{}

	if len(this.Host) > 0 {
		options = append(options, fmt.Sprintf("host=%s", this.Host))
	}

	if this.Port > 0 {
		options = append(options, fmt.Sprintf("port=%d", this.Port))
	}

	if len(this.Name) > 0 {
		options = append(options, fmt.Sprintf("dbname=%s", this.Name))
	}

	if len(this.User) > 0 {
		options = append(options, fmt.Sprintf("user=%s", this.User))
	}

	if len(this.Password) > 0 {
		options = append(options, fmt.Sprintf("password=%s", this.Password))
	}

	options = append(options, "sslmode=disable")

	return strings.Join(options, " ")
}

func (this *DatabaseConfig) MustGetEngine() *xorm.Engine {
	engine, err := xorm.NewEngine("postgres", this.ConnString())
	if err != nil {
		panic(fmt.Sprintf("Got error when connect database, the error is '%v'", err))
	}

	engine.TZLocation = time.UTC

	engine.SetMaxOpenConns(10)
	engine.SetMaxIdleConns(5)

	if this.ShowSql {
		engine.ShowSQL(true)
	}

	if this.ShowError {
		engine.Logger().SetLevel(log.LOG_ERR)
	} else if this.ShowDebug {
		engine.Logger().SetLevel(log.LOG_DEBUG)
	} else {
		engine.Logger().SetLevel(log.LOG_OFF)
	}

	return engine
}
