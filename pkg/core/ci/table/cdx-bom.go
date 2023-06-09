package table

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/alexeyco/simpletable"
)

func CDXBomTable(cdx *cyclonedx.BOM) string{
	var table = simpletable.New()
	bomHeader(table)
	bomRows(cdx.Components, table)
	fmt.Println(table.String())
	return table.String()
}

func bomHeader(table *simpletable.Table) {
	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: "Package"},
			{Align: simpletable.AlignCenter, Text: "Type"},
			{Align: simpletable.AlignCenter, Text: "Version"},
		},
	}
}

func bomRows(components *[]cyclonedx.Component, table *simpletable.Table) {
	for _, c := range *components {
		r := []*simpletable.Cell{
			{Align: simpletable.AlignLeft, Text: c.Name},
			{Text: string(c.Type)},
			{Text: c.Version},
		}
		table.Body.Cells = append(table.Body.Cells, r)
	}
}
