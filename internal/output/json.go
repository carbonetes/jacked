package output

import (
	"encoding/json"

	dm "github.com/carbonetes/diggity/pkg/model"
)

func printJsonResult(results *dm.SBOM) string {
	json, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	return string(json)
}
