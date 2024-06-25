package config

import (
	"os"

	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v2"
)

var Config types.Configuration

var path string = os.Getenv("JACKED_CONFIG")

func init() {
	// Load config from file
	if path == "" {
		// Set the default path
		home, _ := os.UserHomeDir()
		defaultPath := home + string(os.PathSeparator) + ".jacked.yaml"
		path = defaultPath
		os.Setenv("JACKED_CONFIG", path)
	}

	exist, err := helper.IsFileExists(path)
	if err != nil {
		log.Debug("Error checking if config file exists: ", err)
	}

	if !exist {
		// Create the config file
		MakeConfigFile(path)
	}

	// Load the config file
	var config types.Configuration
	ReadConfigFile(&config, path)

	if config.Version != types.ConfigVersion {
		newConfig := New()
		err := mapstructure.Decode(config, &newConfig)
		if err != nil {
			log.Debug(err)
		}
		newConfig.Version = types.ConfigVersion
		ReplaceConfigFile(newConfig, path)
	}
	Config = config

}

// New creates a new configuration with default values
func New() types.Configuration {
	return types.Configuration{
		// Set default values
		Version:     types.ConfigVersion,
		MaxFileSize: 52428800,
	}
}

// MakeConfigFile creates a new configuration file with default values
func MakeConfigFile(path string) {
	// Create the config file
	cfg := New()

	// Write the config file
	err := helper.WriteYAML(cfg, path)
	if err != nil {
		log.Debug("Error writing config file: ", err)
	}
}

func ReadConfigFile(config *types.Configuration, path string) {
	configFile, err := os.ReadFile(path)
	if err != nil {
		log.Debug(err)
	}

	err = yaml.Unmarshal(configFile, config)
	if err != nil {
		log.Debug(err)
	}
}

func ReplaceConfigFile(config types.Configuration, path string) {
	exist, err := helper.IsFileExists(path)
	if err != nil {
		log.Debug(err)
	}

	if exist {
		err = os.Remove(path)
		if err != nil {
			log.Debug(err)
		}
	}

	err = helper.WriteYAML(config, path)
	if err != nil {
		log.Debug(err)
	}
}
