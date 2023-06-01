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
	err := GenerateConfigFile(File, cfg)
	if err != nil {
		log.Error("Error generating config file")
	}
}

// Read the configuration file and parse it
func (cfg *Configuration) Load() *Configuration {
	if _, err := os.Stat(File); err != nil {
		cfg.Generate()
		cfg.Load()
	} else {
		err = LoadConfiguration(File, cfg)
		if err != nil {
			log.Error("Error loading config file")
		}
	}

	if cfg.SecretConfig.Excludes == nil {
		err := cfg.ResetDefault(false)
		if err != nil {
			log.Error("Error resetting config file")
		}
	}

	return cfg
}

// Update the current configuration file
func (cfg *Configuration) Update(test bool) error{
	err := UpdateConfiguration(File, test)
	cfg.Load()
	if !test {
		log.Info("Done!")
	}
	return err
}

// Resets the configuration to default values
func (cfg *Configuration) ResetDefault(test bool) error{
	err:= ResetDefaultConfiguration(File, test)
	cfg.Load()
	if !test{
		log.Info("Done!")
	}
	return err
}
