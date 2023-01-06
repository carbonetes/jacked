package test

import (
	"os"
	"testing"

	"github.com/carbonetes/jacked/internal/config"
)

func TestConfiguration(t *testing.T) {

	var testConfig config.Configuration

	t.Log("Generating test configuration")

	config.Filename = "jacked-test"

	testConfig.Generate()

	t.Log("Loading test configuration")

	testConfig.Load()

	t.Log("Deleting test configuration")
	err := os.Remove(config.File)
	if err != nil {
		t.Fail()
	}
}
