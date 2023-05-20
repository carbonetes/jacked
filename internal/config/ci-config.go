package config

import (
	"os"
)

type CIConfiguration struct {
	FailCriteria             FailCriteria             `yaml:"ignore"`
}

type FailCriteria struct {
	Vulnerability Vulnerability `yaml:"vulnerability"`
	Package       Package       `yaml:"package"`
}

var CIFile  = FileSetter("jackedci")

// Indicate the default value for each configuration
func (cfg *CIConfiguration) CISetDefault() *CIConfiguration {

	DefaultIgnoreVulnerability := Vulnerability{
		CVE:      []string{},
		Severity: []string{},
	}

	DefaultIgnorePackage := Package{
		Name:    []string{},
		Type:    []string{},
		Version: []string{},
	}

	DefaultFailCriteria := FailCriteria{
		Vulnerability: DefaultIgnoreVulnerability,
		Package:       DefaultIgnorePackage,
	}

	cfg.FailCriteria = DefaultFailCriteria

	return cfg
}

// Generate the configuration file with default values
func (cfg *CIConfiguration) CIGenerate() {
	cfg.CISetDefault()
	GenerateConfigFile(CIFile, cfg)
}

// Read the configuration file and parse it
func (cfg *CIConfiguration) CILoad() *CIConfiguration {
	if _, err := os.Stat(CIFile); err != nil {
		cfg.CIGenerate()
		cfg.CILoad()
	} else {
		LoadConfiguration(CIFile, cfg)
	}
	return cfg
}

// Update the current configuration file
func (cfg *CIConfiguration) CIUpdate() {
	UpdateConfiguration(CIFile)
	cfg.CILoad()
	log.Info("Done!")
}

// Resets the configuration to default values
func (cfg *CIConfiguration) CIResetDefault() {
	ResetDefaultConfiguration(CIFile)
	cfg.CILoad()
	log.Info("Done!")
}
