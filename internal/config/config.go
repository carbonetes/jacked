package config

import (
	"os"
	"path/filepath"

	"github.com/carbonetes/jacked/internal/logger"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

type Configuration struct {
	Settings Settings `yaml:"settings"`
	Ignore   Ignore   `yaml:"ignore"`
}

type Settings struct {
	Output  string `yaml:"output"`
	Quiet   bool   `yaml:"quiet"`
	License bool   `yaml:"license"`
	Secret  bool   `yaml:"secret"`
}

type Ignore struct {
	Vulnerability Vulnerability `yaml:"vulnerability"`
	Package       Package       `yaml:"package"`
}

type Vulnerability struct {
	CVE      []string `yaml:"cve"`
	Severity []string `yaml:"severity"`
}

type Package struct {
	Name    []string `yaml:"name"`
	Type    []string `yaml:"type"`
	Version []string `yaml:"version"`
}

var (
	configType = "yaml"
	home, _    = os.UserHomeDir()
	Filename   = "jacked"
	File       = home + string(os.PathSeparator) + "." + Filename + "." + configType
	log        = logger.GetLogger()
)

// Indicate the default value for each configuration
func (cfg *Configuration) SetDefault() *Configuration {
	if len(cfg.Settings.Output) == 0 {
		cfg.Settings.Output = "table"
	}
	return cfg
}

// Generate the configuration file with default values
func (cfg *Configuration) Generate() {
	cfg.SetDefault()
	os.MkdirAll(filepath.Dir(File), 0700)
	out, err := os.OpenFile(File, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("error encoding: %v", err)
	}
	defer out.Close()
	enc := yaml.NewEncoder(out)

	err = enc.Encode(cfg)
	if err != nil {
		log.Fatalf("error encoding: %v", err)
	}
}

// Read the configuration file and parse it
func (cfg *Configuration) Load() *Configuration {
	if _, err := os.Stat(File); err != nil {
		cfg.Generate()
		cfg.Load()
	} else {
		viper.SetConfigFile(File)
		viper.SetConfigType(configType)
		if err := viper.ReadInConfig(); err != nil {
			log.Fatalf("Error reading configurations: %v", err)
		}
		if err := viper.Unmarshal(cfg); err != nil {
			log.Fatalf("Error loading configurations: %v", err)
		}
	}
	return cfg
}

// Update the current configuration file
func (cfg *Configuration) Update() {
	log.Info("Updating configuration...")
	err := os.Remove(File)
	if err != nil {
		log.Fatalf("Error deleting old configuration File: %v", err)
	}
	cfg.Load()
	log.Info("Done!")
}

// Resets the configuration to default values
func (cfg *Configuration) ResetDefault() {
	log.Info("Resetting to default configurations...")
	err := os.Remove(File)
	if err != nil {
		log.Fatalf("Error deleting temp File: %v", err)
	}
	cfg.Load()
	log.Info("Done!")
}
