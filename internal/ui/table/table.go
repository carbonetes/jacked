package table

import (
	"fmt"
	"sort"
	"unicode"

	"github.com/carbonetes/jacked/internal/model"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/alexeyco/simpletable"
)

var table = simpletable.New()

// Constant variables are use as headers when generating table format result.
const (
	Index          string = "#"
	Package        string = "Package"
	Type           string = "Type"
	CurrentVersion string = "Current Version"
	Cve            string = "CVE"
	Score          string = "Score"
	Severity       string = "Severity"
	VersionRange   string = "Affected Versions"
	Total          string = "Vulnerability Found"
)

// Method that generates table header, table rows from the scan result, and displaying the generated table format output.
func DisplayScanResultTable(results []model.ScanResult) {
	createTableHeader()
	createTableRows(results)
	generateTable()
}

// Using the constant variable to generate columns from the table.
func createTableHeader() {

	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: Index},
			{Align: simpletable.AlignCenter, Text: Package},
			{Align: simpletable.AlignCenter, Text: CurrentVersion},
			{Align: simpletable.AlignCenter, Text: Type},
			{Align: simpletable.AlignCenter, Text: Cve},
			{Align: simpletable.AlignCenter, Text: Score},
			{Align: simpletable.AlignCenter, Text: Severity},
			{Align: simpletable.AlignCenter, Text: VersionRange},
		},
	}
}

// From the scan results, table rows will be generated and apply data on a specified table header.
func createTableRows(results []model.ScanResult) {
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Package.Name < results[j].Package.Name
	})
	var index int = 1
	caser := cases.Title(language.English)
	for _, _package := range results {
		for _, v := range _package.Vulnerabilities {
			r := []*simpletable.Cell{
				{Align: simpletable.AlignRight, Text: fmt.Sprintf("%v", index)},
				{Text: elliptical(_package.Package.Name, 33)},
				{Text: elliptical(_package.Package.Version, 18)},
				{Text: _package.Package.Type},
				{Text: v.CVE},
				{Text: fmt.Sprintf("%.1f", v.CVSS.BaseScore)},
				{Text: caser.String(v.CVSS.Severity)},
				{Text: v.VersionRange},
			}
			index++
			table.Body.Cells = append(table.Body.Cells, r)
		}
	}
	createTableFooter(index - 1)
}

// Generate a table footer to show the length of the scan result as total of number of vulnerabilities found.
func createTableFooter(count int) {
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
func generateTable() {
	// Set Table Style
	table.SetStyle(simpletable.StyleCompactLite)
	log.Println(table.String())
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
