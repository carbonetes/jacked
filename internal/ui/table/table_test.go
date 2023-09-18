package table

import (
	"fmt"
	"testing"

	"github.com/alexeyco/simpletable"
	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/pkg/core/model"
)

func TestHeader(t *testing.T) {
	table := simpletable.New()
	header(table)

	expectedHeader := []string{Index, Package, CurrentVersion, Type, Cve, Severity, VersionRange, Fix}

	if len(table.Header.Cells) != len(expectedHeader) {
		t.Errorf("Header length doesn't match, expected %d, got %d", len(expectedHeader), len(table.Header.Cells))
		return
	}

	for i, cell := range table.Header.Cells {
		if cell.Text != expectedHeader[i] {
			t.Errorf("Header cell %d doesn't match, expected '%s', got '%s'", i, expectedHeader[i], cell.Text)
		}
	}
}

func TestElliptical(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"This is a long text", 10, "This is a..."},
		{"Short", 10, "Short"},
		{"Another long text with spaces", 20, "Another long text..."},
	}

	for _, test := range tests {
		result := elliptical(test.input, test.maxLen)
		if result != test.expected {
			t.Errorf("Elliptical(%s, %d) => expected '%s', got '%s'", test.input, test.maxLen, test.expected, result)
		}
	}
}

func TestRows(t *testing.T) {
	table := simpletable.New()
	pkgs := &[]dm.Package{
		{
			Name:    "Package1",
			Version: "1.0.0",
			Type:    "Library",
			Vulnerabilities: &[]model.Vulnerability{
				{
					CVE: "CVE-2021-1234",
					CVSS: model.CVSS{
						Severity: "High",
					},
					Criteria: model.Criteria{
						Constraint: ">=1.0.0",
					},
					Remediation: &model.Remediation{
						Fix: "Upgrade to 1.0.1",
					},
				},
			},
		},
	}

	total := rows(pkgs, table)

	expectedTotal := 2 // Header + 1 vulnerability
	if total != expectedTotal {
		t.Errorf("Rows generated %d rows, expected %d", total, expectedTotal)
	}

	expectedFirstRow := []string{"1", "Package1", "1.0.0", "Library", "CVE-2021-1234", "High", ">=1.0.0", "Upgrade to 1.0.1"}
	actualFirstRow := table.Body.Cells[0]

	for i, cell := range actualFirstRow {
		if cell.Text != expectedFirstRow[i] {
			t.Errorf("Row cell %d doesn't match, expected '%s', got '%s'", i, expectedFirstRow[i], cell.Text)
		}
	}
}

func TestFooter(t *testing.T) {
	table := simpletable.New()
	count := 5

	footer(count, table)

	expectedFooterText := fmt.Sprintf("%s: %v", Total, count)
	if len(table.Footer.Cells) != 1 || table.Footer.Cells[0].Text != expectedFooterText {
		t.Errorf("Footer doesn't match, expected '%s', got '%s'", expectedFooterText, table.Footer.Cells[0].Text)
	}
}
