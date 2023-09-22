package config

import (
	"github.com/cloudbees-compliance/go-common/secretsmanager"
	chstring "github.com/cloudbees-compliance/go-common/strings"
	"github.com/rs/zerolog/log"
	"strings"

	"github.com/spf13/viper"
)

var Config *viper.Viper

func InitConfig() {
	Config = viper.New()
	Config.SetEnvPrefix("ch")
	Config.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	Config.AutomaticEnv()

	Config.SetDefault("server.address", "127.0.0.1")
	Config.SetDefault("server.port", 5004)
	Config.SetDefault("grpc.maxrecvsize", 1*1024*1024*1024) // 1 GiB

	Config.SetDefault("trivy.remote", "http://127.0.0.1:5004")

	Config.SetDefault("service.workerpool.size", 3)
	Config.SetDefault("heartbeat.timer", 45)

	// dev stuff
	Config.SetDefault("log.colour", false)
	Config.SetDefault("log.callerinfo", false)
	Config.SetDefault("log.level", "debug")
	Config.SetDefault("db.log.level", "debug")
	Config.SetDefault("log.useconsolewriter", false)
	Config.SetDefault("log.unixtime", false)

	_ = viper.BindEnv("aws.region", "AWS_REGION")          // err will be ignored
	_ = Config.BindEnv("secret.manager", "SECRET_MANAGER") // err will be ignored
	readSecrets(Config)
}

func readSecrets(config *viper.Viper) {
	source := config.GetString("secret.manager")

	if !chstring.IsEmpty(&source) {
		reader := secretsmanager.GetReader(source)
		if reader != nil {
			secureConfigs, err := reader.Read()
			if err != nil {
				log.Error().Err(err).Msgf("Failed to use secret manager %v", err)
			} else {
				err = config.MergeConfigMap(secureConfigs)
				if err != nil {
					log.Error().Err(err).Msgf("Failed to update secret config %v", err)
				}
			}
		}
	}
}
