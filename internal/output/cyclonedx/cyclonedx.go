package cyclonedx

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"

	"github.com/carbonetes/jacked/internal/model"
	"github.com/carbonetes/jacked/internal/parser"
)

func PrintCycloneDXJSON(results *[]model.ScanResult) {
	cdx := parser.ConvertToCycloneDX(results)

	json, err := json.MarshalIndent(cdx, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", string(json))

}

func PrintCycloneDXXML(results *[]model.ScanResult) {
	cdx := parser.ConvertToCycloneDX(results)

	xml, err := xml.MarshalIndent(cdx, "", " ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%+v\n", string(xml))
}
