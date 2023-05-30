package table

import (
	"fmt"
	"strings"
	simpleTable "github.com/alexeyco/simpletable"
	"github.com/carbonetes/jacked/internal/config"
)

func IgnoreListTable (ignore *config.FailCriteria) string {
	table := simpleTable.New()
	ignoreListHeader(table)
	ignoreListRows(ignore,table)
	fmt.Println(table.String())
	return table.String()
}

func ignoreListHeader(table *simpleTable.Table) {
	table.Header = &simpleTable.Header{
		Cells: []*simpleTable.Cell{
			{Align: simpleTable.AlignCenter, Text: "Ignore"},
			{Align: simpleTable.AlignCenter, Text: "List"},
		},
	}
}

func ignoreListRows(ignore *config.FailCriteria,table *simpleTable.Table) {
	const arraySize = 5
    ignoreLabels := [arraySize]string{"CVE", "Severity", "Name", "Type", "Version"}
	ignoreList := [arraySize]string{strings.Join(ignore.Vulnerability.CVE,","), strings.Join(ignore.Vulnerability.Severity,","), strings.Join(ignore.Package.Name,","), strings.Join(ignore.Package.Type,","), strings.Join(ignore.Package.Version,",")}

	for i:=0; i < arraySize ; i++{
		if len(ignoreList[i]) > 0 {
			 r := []*simpleTable.Cell{
			{Align: simpleTable.AlignLeft, Text: string(ignoreLabels[i])},
			{Align: simpleTable.AlignLeft, Text: string(ignoreList[i])},
			}
			table.Body.Cells = append(table.Body.Cells, r)
		}
	}
}