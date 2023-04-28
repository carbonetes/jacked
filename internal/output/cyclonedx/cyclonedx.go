package cyclonedx

import (
	"encoding/json"
	"encoding/xml"
	"fmt"

	"github.com/carbonetes/diggity/pkg/convert"
	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/internal/logger"
)

var log = logger.GetLogger()

func PrintCycloneDXJSON(sbom *dm.SBOM) {
	cdx := convert.ToCDX(sbom.Packages)
	json, err := json.MarshalIndent(cdx, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", string(json))

}

func PrintCycloneDXXML(sbom *dm.SBOM) {
	cdx := convert.ToCDX(sbom.Packages)
	xml, err := xml.MarshalIndent(cdx, "", " ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%+v\n", string(xml))
}
