package sbom

import (
	"encoding/json"

	dm "github.com/carbonetes/diggity/pkg/model"
)

// Parse sbom and store list of packages and secrets
func ParseSBOM(sbom *[]byte) *dm.SBOM {
	sb := new(dm.SBOM)
	if err := json.Unmarshal(*sbom, sb); err != nil {
		log.Fatalf("Error unmarshalling sbom: %v", err)
	}
	return sb
}
