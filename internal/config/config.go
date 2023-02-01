package config

import (
	"os"
	"path/filepath"

	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/model"

	"gopkg.in/yaml.v2"
)

type Configuration struct {
	Output             string             `yaml:"output"`
	Quiet              bool               `yaml:"quiet"`
	Ignore             Ignore             `yaml:"ignore"`
	EnabledParsers     []string           `yaml:"enabled-parsers"`
	DisableFileListing bool               `yaml:"disable-file-listing"`
	SecretConfig       model.SecretConfig `yaml:"secret-config"`
	LicenseFinder      bool               `yaml:"license-finder"`
	Registry           Registry           `yaml:"registry"`
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

type Registry struct {
	URI      string `yaml:"uri"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Token    string `yaml:"token"`
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

	DefaultSecretConfig := model.SecretConfig{
		Disabled:    true,
		SecretRegex: "API_KEY|SECRET_KEY|DOCKER_AUTH",
		Excludes:    &[]string{},
		MaxFileSize: 10485760,
	}

	DefaultRegistry := Registry{
		URI:      "index.docker.io/",
		Username: "",
		Password: "",
		Token:    "",
	}

	DefaultIgnoreVulnerability := Vulnerability{
		CVE:      []string{},
		Severity: []string{},
	}

	DefaultIgnorePackage := Package{
		Name:    []string{},
		Type:    []string{},
		Version: []string{},
	}

	DefaultIgnore := Ignore{
		Vulnerability: DefaultIgnoreVulnerability,
		Package:       DefaultIgnorePackage,
	}

	cfg.Output = "table"
	cfg.Ignore = DefaultIgnore
	cfg.SecretConfig = DefaultSecretConfig
	cfg.Registry = DefaultRegistry

	return cfg

}

// Generate the configuration file with default values
func (cfg *Configuration) Generate() {
	cfg.SetDefault()
	err := os.MkdirAll(filepath.Dir(File), 0700)
	if err != nil {
		log.Fatalf("Cannot create directory %v", err.Error())
	}
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
		configFile, err := os.ReadFile(File)
		if err != nil {
			log.Fatalf("Error reading configuration file: %v", err)
		}

		err = yaml.Unmarshal(configFile, cfg)
		if err != nil {
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
