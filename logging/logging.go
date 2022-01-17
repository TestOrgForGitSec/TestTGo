package logging

import (
	"compliance-hub-plugin-trivy/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
	"strings"
)

func InitLogging() {
	// colourised logs
	logger := log.Output(zerolog.ConsoleWriter{
		Out:     os.Stderr,
		NoColor: !config.Config.GetBool("log.colour"),
	})

	// filename and line number
	if config.Config.GetBool("log.callerinfo") {
		logger = logger.With().Caller().Logger()
	}
	level, err := zerolog.ParseLevel(config.Config.GetString("log.level"))
	if err != nil {
		level = zerolog.InfoLevel
	}

	log.Logger = logger.Level(level)
}

func GetSubLogger(component string, uuid string) zerolog.Logger {
	// Assume sub log will match the global logger level unless overwritten
	level := log.Logger.GetLevel()

	// Create the sub logger
	logger := log.With()

	if component != "" {
		logger = logger.Str("component", component)
		sLevel := config.Config.GetString("log." + strings.Replace(component, "_", ".", -1))
		if sLevel != "" {
			sublevel, err := zerolog.ParseLevel(sLevel)
			if err == nil {
				level = sublevel
			}
		}
	}
	if uuid != "" {
		logger = logger.Str("uuid", uuid)
	}

	return logger.Logger().Level(level)
}
