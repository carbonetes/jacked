package table

import (
	"fmt"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/alexeyco/simpletable"
	dm "github.com/carbonetes/diggity/pkg/model"
)

// Constant variables are use as headers when generating table format result.
const (
	Index          string = "#"
	Package        string = "Package"
	Type           string = "Type"
	CurrentVersion string = "Current Version"
	Cve            string = "CVE"
	Severity       string = "Severity"
	VersionRange   string = "Affected Versions"
	Fix            string = "Fix"
	Total          string = "Vulnerability Found"
)

// Method that generates table header, table rows from the scan result, and displaying the generated table format output.
func DisplayScanResultTable(pkgs *[]dm.Package) string {
	table := simpletable.New()
	header(table)
	total := rows(pkgs, table)
	if total-1 > 0 {
		footer(total-1, table)
		return display(table)
	} else {
		log.Println("\nNo vulnerabilities found!")
		return ""
	}

}

// Using the constant variable to generate columns from the table.
func header(table *simpletable.Table) {
	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: Index},
			{Align: simpletable.AlignCenter, Text: Package},
			{Align: simpletable.AlignCenter, Text: CurrentVersion},
			{Align: simpletable.AlignCenter, Text: Type},
			{Align: simpletable.AlignCenter, Text: Cve},
			{Align: simpletable.AlignCenter, Text: Severity},
			{Align: simpletable.AlignCenter, Text: VersionRange},
			{Align: simpletable.AlignCenter, Text: Fix},
		},
	}
}

// From the scan results, table rows will be generated and apply data on a specified table header.
func rows(pkgs *[]dm.Package, table *simpletable.Table) int {

	// sort.SliceStable(*pkgs, func(i, j int) bool {
	// 	return (*pkgs)[i].Name < (*pkgs)[j].Name
	// })
	var index int = 1
	caser := cases.Title(language.English)
	for _, p := range *pkgs {
		if p.Vulnerabilities == nil {
			continue
		}
		for _, v := range *p.Vulnerabilities {
			var fix string
			if v.Remediation != nil {
				fix = v.Remediation.Fix
			} else {
				fix = "-"
			}
			r := []*simpletable.Cell{
				{Align: simpletable.AlignRight, Text: fmt.Sprintf("%v", index)},
				{Text: elliptical(p.Name, 26)},
				{Text: elliptical(p.Version, 18)},
				{Text: p.Type},
				{Text: v.CVE},
				{Text: caser.String(v.CVSS.Severity)},
				{Text: elliptical(v.Criteria.Constraint, 15)},
				{Text: fix},
			}
			index++
			table.Body.Cells = append(table.Body.Cells, r)
		}
	}
	return index
}

// Generate a table footer to show the length of the scan result as total of number of vulnerabilities found.
func footer(count int, table *simpletable.Table) {
	table.Footer = &simpletable.Footer{
		Cells: []*simpletable.Cell{
			{
				Span:  8,
				Align: simpletable.AlignLeft,
				Text:  fmt.Sprintf("%s: %v", Total, count),
			},
		},
	}
}

// Set style "StyleCompactLite" to make the table style clean and print out the table.
func display(table *simpletable.Table) string {
	// Set Table Style
	table.SetStyle(simpletable.StyleCompactLite)
	fmt.Println(table.String())
	return table.String()
}

// Handles long text from the table data to generate ellipsis that helps UI table to generated properly.
func elliptical(text string, maxLen int) string {
	lastSpaceIx := maxLen
	len := 0
	for i, r := range text {
		if unicode.IsSpace(r) {
			lastSpaceIx = i
		}
		len++
		if len > maxLen {
			return text[:lastSpaceIx] + "..."
		}
	}
	return text
}
