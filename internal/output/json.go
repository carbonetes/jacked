package output

import (
	"encoding/json"
	"fmt"

	dm "github.com/carbonetes/diggity/pkg/model"
)

func printJsonResult(results *dm.SBOM) {
	json, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(json))
}
