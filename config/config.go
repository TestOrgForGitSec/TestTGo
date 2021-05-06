package config

import (
	"github.com/spf13/viper"
	"strings"
)

var Config *viper.Viper

func InitConfig() {
	Config = viper.New()
	Config.SetEnvPrefix("ch")
	Config.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	Config.AutomaticEnv()

	Config.SetDefault("server.address", "127.0.0.1")
	Config.SetDefault("server.port", 5004)

	Config.SetDefault("trivy.remote", "http://127.0.0.1:5004")

	// dev stuff
	Config.SetDefault("log.colour", false)
	Config.SetDefault("log.callerinfo", false)
	Config.SetDefault("log.level", "debug")
}
