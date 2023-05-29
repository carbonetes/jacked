package output

import (
	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/internal/utils"
)

func printJsonResult(results *dm.SBOM) string {
	json, err := utils.ToJSON(results)
	if err != nil {
		log.Fatal(err)
	}

	return string(json)
}
