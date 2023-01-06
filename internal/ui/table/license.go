package table

import (
	"fmt"

	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/model"

	"github.com/alexeyco/simpletable"
)

var (
	licenseTable = simpletable.New()
	log          = logger.GetLogger()
)

const (
	License       string = "Licenses"
	LicenseFooter string = "License Found: "
)

func licenseHeader() {

	licenseTable.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: Index},
			{Align: simpletable.AlignCenter, Text: Package},
			{Align: simpletable.AlignCenter, Text: License},
		},
	}
}

func licenseRows(licenses []model.License) {
	var index int = 1
	for _, license := range licenses {
		r := []*simpletable.Cell{
			{Align: simpletable.AlignRight, Text: fmt.Sprintf("%v", index)},
			{Text: license.Package},
			{Text: license.License},
		}
		index++
		licenseTable.Body.Cells = append(licenseTable.Body.Cells, r)
	}
	licenseFooter(index - 1)
}

func licenseFooter(count int) {
	licenseTable.Footer = &simpletable.Footer{
		Cells: []*simpletable.Cell{
			{
				Span:  3,
				Align: simpletable.AlignLeft,
				Text:  fmt.Sprintf("%s: %v", "License Found: ", count),
			},
		},
	}
}

func PrintLicenses(licenses []model.License) {
	licenseHeader()
	licenseRows(licenses)
	licenseTable.SetStyle(simpletable.StyleCompactLite)
	log.Println("\nLicenses")
	log.Println(licenseTable.String())
}
