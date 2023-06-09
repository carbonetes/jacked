package table

import (
	"fmt"

	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/pkg/core/model"

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

func licenseRows(licenses []model.License) int{
	var count int = 1
	for _, license := range licenses {
		r := []*simpletable.Cell{
			{Align: simpletable.AlignRight, Text: fmt.Sprintf("%v", count)},
			{Text: license.Package},
			{Text: license.License},
		}
		count++
		licenseTable.Body.Cells = append(licenseTable.Body.Cells, r)
	}
	licenseFooter(count - 1)
	return count -1
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

func PrintLicenses(licenses []model.License) int{
	licenseHeader()
    totalRows := licenseRows(licenses)
	licenseTable.SetStyle(simpletable.StyleCompactLite)
	log.Println("\nLicenses")
	log.Println(licenseTable.String())
	return totalRows
}
