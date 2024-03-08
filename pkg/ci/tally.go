package ci

import (
	"fmt"

	"github.com/alexeyco/simpletable"
)

func TallyTable(tally Tally) string {
	var table = simpletable.New()
	tallyHeader(table)
	tallyRows(tally, table)
	fmt.Println(table.String())

	return table.String()
}

func tallyHeader(table *simpletable.Table) {
	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: "Severity"},
			{Align: simpletable.AlignCenter, Text: "Count"},
		},
	}
}

func tallyRows(tally Tally, table *simpletable.Table) {

	if tally.Unknown != 0 {
		r := []*simpletable.Cell{
			{Align: simpletable.AlignLeft, Text: "Unknown"},
			{Text: fmt.Sprintf("%v", tally.Unknown)},
		}
		table.Body.Cells = append(table.Body.Cells, r)
	}
	if tally.Negligible != 0 {
		r := []*simpletable.Cell{
			{Align: simpletable.AlignLeft, Text: "Negligible"},
			{Text: fmt.Sprintf("%v", tally.Negligible)},
		}
		table.Body.Cells = append(table.Body.Cells, r)
	}
	if tally.Low != 0 {
		r := []*simpletable.Cell{
			{Align: simpletable.AlignLeft, Text: "Low"},
			{Text: fmt.Sprintf("%v", tally.Low)},
		}
		table.Body.Cells = append(table.Body.Cells, r)
	}
	if tally.Medium != 0 {
		r := []*simpletable.Cell{
			{Align: simpletable.AlignLeft, Text: "Medium"},
			{Text: fmt.Sprintf("%v", tally.Medium)},
		}
		table.Body.Cells = append(table.Body.Cells, r)
	}
	if tally.High != 0 {
		r := []*simpletable.Cell{
			{Align: simpletable.AlignLeft, Text: "High"},
			{Text: fmt.Sprintf("%v", tally.High)},
		}
		table.Body.Cells = append(table.Body.Cells, r)
	}
	if tally.Critical != 0 {
		r := []*simpletable.Cell{
			{Align: simpletable.AlignLeft, Text: "Critical"},
			{Text: fmt.Sprintf("%v", tally.Critical)},
		}
		table.Body.Cells = append(table.Body.Cells, r)
	}
}
