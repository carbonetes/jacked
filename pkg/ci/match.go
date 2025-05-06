package ci

import (
	"fmt"

	"github.com/alexeyco/simpletable"
)

func MatchTable(matches []Match) {
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
			{Align: simpletable.AlignCenter, Text: "Type"},
		},
	}
}

func matchRows(matches []Match, table *simpletable.Table) {
	for _, m := range matches {
		r := []*simpletable.Cell{
			{Text: string(m.Component.Name)},
			{Text: string(m.Vulnerability.ID)},
			{Text: getSeverity(m.Vulnerability.Ratings)},
			{Text: string(m.Type)},
		}
		table.Body.Cells = append(table.Body.Cells, r)
	}
}
