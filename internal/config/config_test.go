package config

import (
	"testing"
	"os"
)

var(
	cfg = 		 new(Configuration)
	ciCfg = 	 new(CIConfiguration)
	filename = 	 FileSetter("jackedTest")
	ciFilename = FileSetter("jackedCiTest")
)

func TestGenerateConfigFile(t *testing.T) {
	err:= GenerateConfigFile(filename, cfg)
	if err != nil{
		t.Error("Failed: Error on generating config file")
	}

	err = GenerateConfigFile(ciFilename, ciCfg)
	if err != nil{
		t.Error("Failed: Error on generating CI config file")
	}
}

func TestLoadConfiguration(t *testing.T) {
	err := LoadConfiguration(filename, cfg)
	if err != nil{
		t.Error("Failed: Error on loading config file")
	}

	err = LoadConfiguration(ciFilename, ciCfg)
	if err != nil{
		t.Error("Failed: Error on loading CI config file")
	}

}

func TestUpdate(t *testing.T) {
	err := cfg.Update(true)
	if err != nil{
		t.Error("Failed: Error on updating config file")
	}

	err = ciCfg.CIUpdate(true)
	if err != nil{
		t.Error("Failed: Error on updating CI config file")
	}
}

func TestResetDefault(t *testing.T) {
	err := cfg.ResetDefault(true)
	if err != nil{
		t.Error("Failed: Error on resetting config file")
	}

	err = ciCfg.CIResetDefault(true)
	if err != nil{
		t.Error("Failed: Error on resetting CI config file")
	}

	err = os.Remove(filename)
	if err != nil {
		log.Fatalf("Error deleting temp File: %v", err)
	}
	err = os.Remove(ciFilename)
	if err != nil {
		log.Fatalf("Error deleting temp File: %v", err)
	}
}