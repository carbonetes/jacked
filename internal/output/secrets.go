package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"

	dm "github.com/carbonetes/diggity/pkg/model"
)

func PrintJsonSecret(secrets *dm.SecretResults) {
	json, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(json))
}

func PrintXMLSecret(secrets *dm.SecretResults) {
	xml, err := xml.MarshalIndent(secrets, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", string(xml))
}
