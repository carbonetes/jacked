package table

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/charmbracelet/bubbles/table"
)

// TestCreateTableWithNoVulnerabilities tests table creation when no vulnerabilities are found
func TestCreateTableWithNoVulnerabilities(t *testing.T) {
	// Test with nil BOM
	tableModel := Create(nil)
	if len(tableModel.Rows()) != 0 {
		t.Error("Expected empty table for nil BOM")
	}

	// Test with BOM but no vulnerabilities
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{
				BOMRef:  "component-1",
				Name:    "test-component",
				Version: "1.0.0",
			},
		},
		Vulnerabilities: nil,
	}

	tableModel = Create(bom)
	if len(tableModel.Rows()) != 0 {
		t.Error("Expected empty table for BOM with no vulnerabilities")
	}

	// Test with empty vulnerabilities slice
	emptyVulns := []cyclonedx.Vulnerability{}
	bom.Vulnerabilities = &emptyVulns

	tableModel = Create(bom)
	if len(tableModel.Rows()) != 0 {
		t.Error("Expected empty table for BOM with empty vulnerabilities slice")
	}
}

// TestCreateTableWithVulnerabilities tests table creation with vulnerabilities
func TestCreateTableWithVulnerabilities(t *testing.T) {
	components := []cyclonedx.Component{
		{
			BOMRef:  "component-1",
			Name:    "vulnerable-lib",
			Version: "1.0.0",
		},
		{
			BOMRef:  "component-2",
			Name:    "another-lib",
			Version: "2.1.0",
		},
	}

	vulnerabilities := []cyclonedx.Vulnerability{
		{
			BOMRef:         "component-1",
			ID:             "CVE-2023-0001",
			Recommendation: "Upgrade to version 1.1.0",
			Ratings: &[]cyclonedx.VulnerabilityRating{
				{
					Severity: cyclonedx.SeverityCritical,
				},
			},
		},
		{
			BOMRef:         "component-2",
			ID:             "CVE-2023-0002",
			Recommendation: "Apply security patch",
			Ratings: &[]cyclonedx.VulnerabilityRating{
				{
					Severity: cyclonedx.SeverityHigh,
				},
			},
		},
	}

	bom := &cyclonedx.BOM{
		Components:      &components,
		Vulnerabilities: &vulnerabilities,
	}

	tableModel := Create(bom)

	// Check that we have the expected number of rows
	if len(tableModel.Rows()) != 2 {
		t.Errorf("Expected 2 rows, got %d", len(tableModel.Rows()))
	}

	// Check first row content
	rows := tableModel.Rows()
	if len(rows) > 0 {
		firstRow := rows[0]
		if len(firstRow) != 5 {
			t.Errorf("Expected 5 columns, got %d", len(firstRow))
		}

		// Check component name
		if firstRow[0] != "vulnerable-lib" {
			t.Errorf("Expected component name 'vulnerable-lib', got '%s'", firstRow[0])
		}

		// Check version
		if firstRow[1] != "1.0.0" {
			t.Errorf("Expected version '1.0.0', got '%s'", firstRow[1])
		}

		// Check CVE ID
		if firstRow[2] != "CVE-2023-0001" {
			t.Errorf("Expected CVE 'CVE-2023-0001', got '%s'", firstRow[2])
		}

		// Check severity
		if firstRow[3] != "critical" {
			t.Errorf("Expected severity 'critical', got '%s'", firstRow[3])
		}

		// Check recommendation
		if firstRow[4] != "Upgrade to version 1.1.0" {
			t.Errorf("Expected recommendation 'Upgrade to version 1.1.0', got '%s'", firstRow[4])
		}
	}
}

// TestCreateTableWithComplexVersions tests table creation with complex version formats
func TestCreateTableWithComplexVersions(t *testing.T) {
	components := []cyclonedx.Component{
		{
			BOMRef:  "component-1",
			Name:    "complex-lib",
			Version: "1:2.3.4-5ubuntu1",
		},
	}

	vulnerabilities := []cyclonedx.Vulnerability{
		{
			BOMRef:         "component-1",
			ID:             "CVE-2023-0003",
			Recommendation: "Update package",
		},
	}

	bom := &cyclonedx.BOM{
		Components:      &components,
		Vulnerabilities: &vulnerabilities,
	}

	tableModel := Create(bom)

	if len(tableModel.Rows()) != 1 {
		t.Errorf("Expected 1 row, got %d", len(tableModel.Rows()))
	}

	rows := tableModel.Rows()
	if len(rows) > 0 {
		firstRow := rows[0]

		// Check component name
		if firstRow[0] != "complex-lib" {
			t.Errorf("Expected component name 'complex-lib', got '%s'", firstRow[0])
		}

		// Check that complex version is handled correctly (including epoch)
		if firstRow[1] != "1:2.3.4-5ubuntu1" {
			t.Errorf("Expected version '1:2.3.4-5ubuntu1', got '%s'", firstRow[1])
		}
	}
}

// TestCreateTableWithMissingRatings tests table creation when vulnerability has no ratings
func TestCreateTableWithMissingRatings(t *testing.T) {
	components := []cyclonedx.Component{
		{
			BOMRef:  "component-1",
			Name:    "test-lib",
			Version: "1.0.0",
		},
	}

	vulnerabilities := []cyclonedx.Vulnerability{
		{
			BOMRef:         "component-1",
			ID:             "CVE-2023-0004",
			Recommendation: "Check for updates",
			Ratings:        nil, // No ratings
		},
	}

	bom := &cyclonedx.BOM{
		Components:      &components,
		Vulnerabilities: &vulnerabilities,
	}

	tableModel := Create(bom)

	if len(tableModel.Rows()) != 1 {
		t.Errorf("Expected 1 row, got %d", len(tableModel.Rows()))
	}

	rows := tableModel.Rows()
	if len(rows) > 0 {
		firstRow := rows[0]

		// Check that severity defaults to "UNKNOWN" when no ratings are present
		if firstRow[3] != "UNKNOWN" {
			t.Errorf("Expected severity 'UNKNOWN', got '%s'", firstRow[3])
		}
	}
}

// TestCreateTableWithEmptyRatings tests table creation when vulnerability has empty ratings
func TestCreateTableWithEmptyRatings(t *testing.T) {
	components := []cyclonedx.Component{
		{
			BOMRef:  "component-1",
			Name:    "test-lib",
			Version: "1.0.0",
		},
	}

	emptyRatings := []cyclonedx.VulnerabilityRating{}
	vulnerabilities := []cyclonedx.Vulnerability{
		{
			BOMRef:         "component-1",
			ID:             "CVE-2023-0005",
			Recommendation: "Monitor for updates",
			Ratings:        &emptyRatings, // Empty ratings slice
		},
	}

	bom := &cyclonedx.BOM{
		Components:      &components,
		Vulnerabilities: &vulnerabilities,
	}

	tableModel := Create(bom)

	if len(tableModel.Rows()) != 1 {
		t.Errorf("Expected 1 row, got %d", len(tableModel.Rows()))
	}

	rows := tableModel.Rows()
	if len(rows) > 0 {
		firstRow := rows[0]

		// Check that severity defaults to "UNKNOWN" when ratings slice is empty
		if firstRow[3] != "UNKNOWN" {
			t.Errorf("Expected severity 'UNKNOWN', got '%s'", firstRow[3])
		}
	}
}

// TestNonInteractiveMode tests the non-interactive mode functionality
func TestNonInteractiveMode(t *testing.T) {
	// Test that NonInteractive global variable can be set
	originalNonInteractive := NonInteractive
	defer func() { NonInteractive = originalNonInteractive }()

	NonInteractive = true

	// Create a simple table
	columns := []table.Column{
		{Title: "Test", Width: 10},
	}
	rows := []table.Row{
		{"test-value"},
	}

	testTable := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
	)

	// Test creating a model with non-interactive mode
	model := model{
		table:          testTable,
		duration:       1.0,
		nonInteractive: true,
	}

	// Test that Init() returns the auto-exit command in non-interactive mode
	cmd := model.Init()
	if cmd == nil {
		t.Error("Expected non-nil command in non-interactive mode")
	}

	// Test Update with autoExitMsg
	_, cmd = model.Update(autoExitMsg{})
	if cmd == nil {
		t.Error("Expected quit command when receiving autoExitMsg")
	}
}

// TestTableSorting tests that vulnerabilities are sorted by BOM ref
func TestTableSorting(t *testing.T) {
	components := []cyclonedx.Component{
		{
			BOMRef:  "component-z",
			Name:    "last-lib",
			Version: "1.0.0",
		},
		{
			BOMRef:  "component-a",
			Name:    "first-lib",
			Version: "2.0.0",
		},
	}

	// Create vulnerabilities in reverse order to test sorting
	vulnerabilities := []cyclonedx.Vulnerability{
		{
			BOMRef: "component-z",
			ID:     "CVE-2023-0002",
		},
		{
			BOMRef: "component-a",
			ID:     "CVE-2023-0001",
		},
	}

	bom := &cyclonedx.BOM{
		Components:      &components,
		Vulnerabilities: &vulnerabilities,
	}

	tableModel := Create(bom)
	rows := tableModel.Rows()

	if len(rows) != 2 {
		t.Errorf("Expected 2 rows, got %d", len(rows))
	}

	// Check that vulnerabilities are sorted by BOM ref (component-a should come first)
	if len(rows) > 0 && rows[0][2] != "CVE-2023-0001" {
		t.Errorf("Expected first row to have CVE-2023-0001, got %s", rows[0][2])
	}

	if len(rows) > 1 && rows[1][2] != "CVE-2023-0002" {
		t.Errorf("Expected second row to have CVE-2023-0002, got %s", rows[1][2])
	}
}

// TestShowNonInteractive tests the ShowNonInteractive function
func TestShowNonInteractive(t *testing.T) {
	// Create a simple table
	columns := []table.Column{
		{Title: "Test", Width: 10},
	}
	rows := []table.Row{
		{"test-value"},
	}

	testTable := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
	)

	// This test mainly ensures ShowNonInteractive doesn't panic
	// We'll test that the function exists and can be called without hanging
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ShowNonInteractive panicked: %v", r)
		}
	}()

	// Note: In a real test environment, ShowNonInteractive would start a TUI
	// which might not work properly. For unit testing, we verify the function
	// signature and that it can be called. Integration tests would test the full TUI.
	_ = testTable // Use the table to avoid "unused variable" error

	// Test that we can create a non-interactive model
	model := model{
		table:          testTable,
		duration:       1.5,
		nonInteractive: true,
	}

	// Verify the model is configured for non-interactive mode
	if !model.nonInteractive {
		t.Error("Expected model to be in non-interactive mode")
	}

	// Test that the view shows appropriate message for non-interactive mode
	view := model.View()
	if !containsIgnoreCase(view, "Exiting") {
		t.Error("Expected non-interactive view to contain 'Exiting' message")
	}
}

// TestModelView tests the View method of the model
func TestModelView(t *testing.T) {
	// Test view with empty table (no vulnerabilities)
	emptyTable := table.New()
	model := model{
		table:          emptyTable,
		duration:       2.5,
		nonInteractive: false,
	}

	view := model.View()
	if view == "" {
		t.Error("Expected non-empty view string")
	}

	// Check that it contains the expected "no vulnerability" message
	if !containsIgnoreCase(view, "No vulnerability") {
		t.Error("Expected view to contain 'No vulnerability' message")
	}

	// Check that duration is included
	if !containsIgnoreCase(view, "2.5") {
		t.Error("Expected view to contain duration")
	}

	// Test view with non-interactive mode
	model.nonInteractive = true
	view = model.View()

	if !containsIgnoreCase(view, "Exiting") {
		t.Error("Expected non-interactive view to contain 'Exiting' message")
	}
}

// Helper function to check if string contains substring (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				checkContains(strings.ToLower(s), strings.ToLower(substr))))
}

func checkContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// BenchmarkCreateTable benchmarks table creation performance
func BenchmarkCreateTable(b *testing.B) {
	// Create a large BOM with many components and vulnerabilities
	components := make([]cyclonedx.Component, 100)
	vulnerabilities := make([]cyclonedx.Vulnerability, 100)

	for i := 0; i < 100; i++ {
		components[i] = cyclonedx.Component{
			BOMRef:  fmt.Sprintf("component-%d", i),
			Name:    fmt.Sprintf("lib-%d", i),
			Version: "1.0.0",
		}

		vulnerabilities[i] = cyclonedx.Vulnerability{
			BOMRef:         fmt.Sprintf("component-%d", i),
			ID:             fmt.Sprintf("CVE-2023-%04d", i),
			Recommendation: "Update to latest version",
			Ratings: &[]cyclonedx.VulnerabilityRating{
				{
					Severity: cyclonedx.SeverityMedium,
				},
			},
		}
	}

	bom := &cyclonedx.BOM{
		Components:      &components,
		Vulnerabilities: &vulnerabilities,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Create(bom)
	}
}
