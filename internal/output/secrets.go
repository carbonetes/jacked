package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"

	"github.com/carbonetes/jacked/internal/model"
)

func printJsonSecret(secrets *model.SecretResults) {
	json, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(json))
}

func PrintXMLSecret(secrets *model.SecretResults) {
	xml, err := xml.MarshalIndent(secrets, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", string(xml))
}
