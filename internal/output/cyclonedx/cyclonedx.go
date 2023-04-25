package cyclonedx

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"

	"github.com/carbonetes/jacked/internal/parser"
	"github.com/carbonetes/jacked/pkg/core/model"
)

func PrintCycloneDXJSON(results *[]model.ScanResult) string{
	cdx := parser.ConvertToCycloneDX(results)

	json, err := json.MarshalIndent(cdx, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", string(json))
	return string(json)

}

func PrintCycloneDXXML(results *[]model.ScanResult) string{
	cdx := parser.ConvertToCycloneDX(results)

	xml, err := xml.MarshalIndent(cdx, "", " ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%+v\n", string(xml))
	return string(xml)
}
