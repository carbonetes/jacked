package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v2"
)

var Config types.Configuration

var path string = os.Getenv("JACKED_CONFIG")

// isValidParentDir checks if the parent directory of a path exists and is writable
func isValidParentDir(filePath string) bool {
	if filePath == "" {
		return false
	}
	
	dir := filepath.Dir(filePath)
	if dir == "." || dir == "/" {
		return true // Current dir or root are typically valid
	}
	
	// Check if parent directory exists
	info, err := os.Stat(dir)
	if err != nil {
		return false
	}
	
	return info.IsDir()
}

// SetConfigPath allows setting a custom configuration file path
func SetConfigPath(customPath string) {
	path = customPath
	os.Setenv("JACKED_CONFIG", path)
}

func ReloadConfig() error {
	// Validate path is not empty
	if path == "" {
		return fmt.Errorf("config path is empty")
	}

	log.Debug(fmt.Sprintf("ReloadConfig: checking path '%s'", path))
	exist, err := helper.IsFileExists(path)
	if err != nil {
		log.Debug("Error checking if config file exists: ", err)
		return err
	}

	log.Debug(fmt.Sprintf("ReloadConfig: path '%s' exists=%v", path, exist))
	if !exist {
		// Check if parent directory exists for the path
		if !isValidParentDir(path) {
			return fmt.Errorf("invalid config path (parent directory does not exist): %s", path)
		}
		
		// Create the config file
		MakeConfigFile(path)
	}

	// Load the config file
	var config types.Configuration
	err = ReadConfigFile(&config, path)
	if err != nil {
		log.Debug("Error reading config file in ReloadConfig: ", err)
		return err
	}

	if config.Version != types.ConfigVersion {
		newConfig := New()
		err := mapstructure.Decode(config, &newConfig)
		if err != nil {
			log.Debug(err)
			return err
		}
		newConfig.Version = types.ConfigVersion
		ReplaceConfigFile(newConfig, path)
		Config = newConfig
	} else {
		Config = config
	}

	return nil
}

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
	err = ReadConfigFile(&config, path)
	if err != nil {
		log.Debug("Error reading config file in init: ", err)
		// In init, we can't return error, so fall back to defaults
		Config = New()
		return
	}

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

// GetConfigPath returns the current configuration file path
func GetConfigPath() string {
	return path
}

// DisplayConfig prints the current configuration for debugging
func DisplayConfig() {
	log.Debugf("Current config path: %s", path)
	log.Debugf("Max concurrent scanners: %d", Config.Performance.MaxConcurrentScanners)
	log.Debugf("Max file size: %d", Config.MaxFileSize)
	log.Debugf("Cache enabled: %v", Config.Performance.EnableCaching)
}

// New creates a new configuration with default values
func New() types.Configuration {
	return types.Configuration{
		// Set default values
		Version:     types.ConfigVersion,
		MaxFileSize: 52428800,
		Performance: types.GetAdvancedPerformanceConfig(),
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

func ReadConfigFile(config *types.Configuration, path string) error {
	configFile, err := os.ReadFile(path)
	if err != nil {
		log.Debug(err)
		return err
	}

	err = yaml.Unmarshal(configFile, config)
	if err != nil {
		log.Debug(err)
		return err
	}
	
	return nil
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

// LoadConfigFromPath loads configuration from a specific file path
func LoadConfigFromPath(configPath string) error {
	exist, err := helper.IsFileExists(configPath)
	if err != nil {
		return err
	}

	if !exist {
		return os.ErrNotExist
	}

	var config types.Configuration
	err = ReadConfigFile(&config, configPath)
	if err != nil {
		return err
	}

	if config.Version != types.ConfigVersion {
		newConfig := New()
		err := mapstructure.Decode(config, &newConfig)
		if err != nil {
			return err
		}
		newConfig.Version = types.ConfigVersion
		Config = newConfig
	} else {
		Config = config
	}

	return nil
}
