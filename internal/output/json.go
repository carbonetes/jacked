package output

import (
	"encoding/json"
	"fmt"

	"github.com/carbonetes/jacked/internal/model"
)

func printJsonResult(results *[]model.ScanResult) {
	json, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(json))
}
