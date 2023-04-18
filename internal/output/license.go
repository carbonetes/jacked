package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"

	"github.com/carbonetes/jacked/pkg/core/model"
)

func PrintJsonLicense(licenses *[]model.License) {
	json, err := json.MarshalIndent(licenses, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(json))
}

func PrintXMLLicense(licenses *[]model.License) {
	xml, err := xml.MarshalIndent(licenses, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", string(xml))
}
