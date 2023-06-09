package config

import (
	"os"
	"path/filepath"

	"github.com/carbonetes/jacked/internal/logger"

	"gopkg.in/yaml.v2"
)

var log   = logger.GetLogger()

type Vulnerability struct {
	CVE      []string `yaml:"cve"`
	Severity []string `yaml:"severity"`
}

type Package struct {
	Name    []string `yaml:"name"`
	Type    []string `yaml:"type"`
	Version []string `yaml:"version"`
}

func FileSetter (filename string) string{
	var(
		configType = "yaml"
		home, _    = os.UserHomeDir()
	)

	return home + string(os.PathSeparator) + "." + filename + "." + configType
}

func GenerateConfigFile (filename string , cfg interface{}) error{
	err := os.MkdirAll(filepath.Dir(filename), 0700)
	if err != nil {
		log.Fatalf("Cannot create directory %v", err.Error())
	}
	out, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("error encoding: %v", err)
	}
	defer out.Close()
	enc := yaml.NewEncoder(out)

	err = enc.Encode(cfg)
	if err != nil {
		log.Fatalf("error encoding: %v", err)
	}
	return err
}

func LoadConfiguration(filename string, cfg interface{}) error{
	configFile, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("Error reading configuration file: %v", err)
	}
	
	err = yaml.Unmarshal(configFile, cfg)
	if err != nil {
		log.Fatalf("Error loading configurations: %v", err)
	}
	return err
}

func UpdateConfiguration (filename string) error{
	log.Info("Updating configuration...")
	err := os.Remove(filename)
	if err != nil {
		log.Fatalf("Error deleting old configuration File: %v", err)
	}
	return err
}

func ResetDefaultConfiguration (filename string) error{
	log.Info("Resetting to default configurations...")
	err := os.Remove(filename)
	if err != nil {
		log.Fatalf("Error deleting temp File: %v", err)
	}
	return err
}