package parser

import (
	"encoding/json"

	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/model"
)

var log = logger.GetLogger()

// Parse sbom and store list of packages and secrets
func ParseSBOM(sbom *[]byte, pkgs *[]model.Package, secrets *model.SecretResults) {
	var sb model.SBOM

	if err := json.Unmarshal(*sbom, &sb); err != nil {
		log.Fatalf("Error unmarshalling sbom: %v", err)
	}

	if err := json.Unmarshal([]byte(sb.Packages), pkgs); err != nil {
		log.Fatalf("Error unmarshalling packages: %v", err)
	}
	if err := json.Unmarshal([]byte(sb.Secrets), secrets); err != nil {
		log.Fatalf("Error unmarshalling secrets: %v", err)
	}

}
