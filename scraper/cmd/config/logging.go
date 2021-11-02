package config

import (
	"fmt"
	stdlog "log"
	"os"

	ini "github.com/nanitor/goini"
	"github.com/op/go-logging"
)

type LoggingConfig struct {
	EnableConsole bool
	EnableFile    bool
	LogLevel      string
	LogFile       string
	TruncateSize  int64 // Size in bytes where the logfile gets truncated if it exceed a particular size.
}

func LoggingConfigFromDict(dict ini.Dict, cmdSectionName string) (*LoggingConfig, error) {
	sectionName := cmdSectionName + ":logging"

	ret := LoggingConfig{}
	ret.EnableConsole = dict.GetBoolDef(sectionName, "enable_console", true)
	ret.EnableFile = dict.GetBoolDef(sectionName, "enable_file", false)
	ret.LogLevel = dict.GetStringDef(sectionName, "loglevel", "info")

	if ret.EnableFile {
		ret.LogFile = dict.GetStringDef(sectionName, "logfile", "")
		if ret.LogFile == "" {
			return nil, fmt.Errorf("Logging logfile enabled, but not specified")
		}
	}

	return &ret, nil
}

func (this *LoggingConfig) GetLevel() logging.Level {
	level := logging.INFO
	switch this.LogLevel {
	case "debug":
		level = logging.DEBUG
	case "notice":
		level = logging.NOTICE
	case "info":
		level = logging.INFO
	case "warning":
		level = logging.WARNING
	case "error":
		level = logging.ERROR
	case "critical":
		level = logging.CRITICAL
	}

	return level
}

func (this *LoggingConfig) shouldTruncate() bool {
	if this.TruncateSize <= 0 {
		return false
	}

	fi, err := os.Stat(this.LogFile)
	if err != nil {
		return false
	}

	return fi.Size() >= this.TruncateSize
}

func (this *LoggingConfig) Configure() (*logging.Logger, error) {
	logging.SetFormatter(logging.MustStringFormatter("%{longpkg} ▶ %{level:.1s} 0x%{id:x} %{message}"))
	var backends []logging.Backend

	flags := stdlog.LstdFlags
	if this.LogLevel == "debug" {
		flags |= stdlog.Lshortfile
	}

	if this.EnableConsole {
		logBackend := logging.NewLogBackend(os.Stderr, "", flags)
		logBackend.Color = true
		backends = append(backends, logBackend)
	}

	if this.EnableFile {
		modes := os.O_RDWR | os.O_CREATE

		if this.shouldTruncate() {
			modes |= os.O_TRUNC
		} else {
			modes |= os.O_APPEND
		}

		file, err := os.OpenFile(this.LogFile, modes, 0660)
		if err != nil {
			return nil, err
		}

		logBackend := logging.NewLogBackend(file, "", flags)
		logBackend.Color = true
		backends = append(backends, logBackend)
	}

	backend := logging.SetBackend(backends...)
	backend.SetLevel(this.GetLevel(), "")

	// Initialise logger.
	return logging.GetLogger("main")
}
