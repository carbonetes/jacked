package table

import (
	"fmt"
	"sort"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/alexeyco/simpletable"
)

func CDXVexTable(cdx *cyclonedx.BOM) {
	var table = simpletable.New()
	vexHeader(table)
	vexRows(cdx.Vulnerabilities, table)
	fmt.Println(table.String())
}

func vexHeader(table *simpletable.Table) {
	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: "Vulnerability"},
			{Align: simpletable.AlignCenter, Text: "Severity"},
			{Align: simpletable.AlignCenter, Text: "Recommendation"},
		},
	}
}

func vexRows(vulnerabilities *[]cyclonedx.Vulnerability, table *simpletable.Table) {
	sort.SliceStable(*vulnerabilities, func(i, j int) bool {
		return (*vulnerabilities)[i].ID < (*vulnerabilities)[j].ID
	})
	for _, v := range *vulnerabilities {
		var recommendation string
		if len(v.Recommendation) > 0 {
			recommendation = v.Recommendation
		} else {
			recommendation = "-"
		}
		r := []*simpletable.Cell{
			{Align: simpletable.AlignLeft, Text: v.ID},
			{Align: simpletable.AlignLeft, Text: getSeverity(v.Ratings)},
			{Align: simpletable.AlignLeft, Text: recommendation},
		}
		table.Body.Cells = append(table.Body.Cells, r)
	}
}

func getSeverity(ratings *[]cyclonedx.VulnerabilityRating) string {
	if len(*ratings) == 0 {
		return "UNKNOWN"
	}

	for _, rating := range *ratings {
		if len(rating.Severity) > 0 {
			return string(rating.Severity)
		}
	}
	return "UNKNOWN"
}
