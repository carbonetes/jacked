package config

import (
	"os"

	"github.com/carbonetes/jacked/pkg/core/model"

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

type Registry struct {
	URI      string `yaml:"uri"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Token    string `yaml:"token"`
}

var File  = FileSetter("jacked")
	



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
	GenerateConfigFile(File, cfg)
}

// Read the configuration file and parse it
func (cfg *Configuration) Load() *Configuration {
	if _, err := os.Stat(File); err != nil {
		cfg.Generate()
		cfg.Load()
	} else {
		LoadConfiguration(File, cfg)
	}

	if cfg.SecretConfig.Excludes == nil {
		cfg.ResetDefault()
	}

	return cfg
}

// Update the current configuration file
func (cfg *Configuration) Update() {
	UpdateConfiguration(File)
	cfg.Load()
	log.Info("Done!")
}

// Resets the configuration to default values
func (cfg *Configuration) ResetDefault() {
	ResetDefaultConfiguration(File)
	cfg.Load()
	log.Info("Done!")
}
