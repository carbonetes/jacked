package cyclonedx

import (
	"encoding/xml"
	"fmt"

	"github.com/carbonetes/diggity/pkg/convert"
	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/utils"
)

var log = logger.GetLogger()

func PrintCycloneDXJSON(sbom *dm.SBOM) string {
	cdx := convert.ToCDX(sbom.Packages)
	json, err := utils.ToJSON(cdx)
	if err != nil {
		log.Fatal(err)
	}
    fmt.Printf("%s\n", string(json))
	return string(json)

}

func PrintCycloneDXXML(sbom *dm.SBOM) string {
	cdx := convert.ToCDX(sbom.Packages)
	xml, err := xml.MarshalIndent(cdx, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", string(xml))
	return string(xml)
}
