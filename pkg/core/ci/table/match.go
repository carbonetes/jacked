package table

import (
	"fmt"

	"github.com/alexeyco/simpletable"
	"github.com/carbonetes/jacked/pkg/core/ci/assessment"
)

func MatchTable(matches *[]assessment.Match) {
	var table = simpletable.New()
	matchHeader(table)
	matchRows(matches, table)
	fmt.Println(table.String())
}

func matchHeader(table *simpletable.Table) {
	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: "Package"},
			{Align: simpletable.AlignCenter, Text: "CVE"},
			{Align: simpletable.AlignCenter, Text: "Severity"},
		},
	}
}

func matchRows(matches *[]assessment.Match, table *simpletable.Table) {
	for _, m := range *matches {
		r := []*simpletable.Cell{
			{Text: string(m.Component.Name)},
			{Text: string(m.Vulnerability.ID)},
			{Text: getSeverity(m.Vulnerability.Ratings)},
		}
		table.Body.Cells = append(table.Body.Cells, r)
	}
}
