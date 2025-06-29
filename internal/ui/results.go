package ui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/types"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

// ANSI color codes for severity levels
const (
	ColorReset    = "\033[0m"
	ColorCritical = "\033[91m" // Bright Red
	ColorHigh     = "\033[31m" // Red
	ColorMedium   = "\033[33m" // Yellow
	ColorLow      = "\033[93m" // Bright Yellow
	ColorUpgrade  = "\033[96m" // Cyan
	ColorUnknown  = "\033[37m" // Gray
	ColorAdvisory = "\033[94m" // Blue
)

// ResultsViewer provides an enhanced TUI for viewing scan results
type ResultsViewer struct {
	params  types.Parameters
	bom     *cyclonedx.BOM
	elapsed time.Duration
}

// NewResultsViewer creates a new results viewer
func NewResultsViewer(params types.Parameters, bom *cyclonedx.BOM, elapsed time.Duration) *ResultsViewer {
	return &ResultsViewer{
		params:  params,
		bom:     bom,
		elapsed: elapsed,
	}
}

// ShowResults displays the results using the enhanced TUI
func (rv *ResultsViewer) ShowResults(ctx context.Context) error {
	// Create the main model with results ready
	model := NewMainModel(rv.params, rv.bom)
	model.state = ViewResults
	model.scanDuration = rv.elapsed

	if rv.bom != nil && rv.bom.Vulnerabilities != nil {
		model.vulnCount = len(*rv.bom.Vulnerabilities)
	}

	// Calculate statistics and populate table
	(&model).calculateStats()
	(&model).populateTable()

	// Create and run the Bubble Tea program
	p := tea.NewProgram(model, tea.WithAltScreen())

	_, err := p.Run()
	return err
}

// ShowResultsInline displays results without taking over the entire screen
func (rv *ResultsViewer) ShowResultsInline(ctx context.Context) error {
	// Create the main model with results ready
	model := NewMainModel(rv.params, rv.bom)
	model.state = ViewResults
	model.scanDuration = rv.elapsed

	if rv.bom != nil && rv.bom.Vulnerabilities != nil {
		model.vulnCount = len(*rv.bom.Vulnerabilities)
	}

	// Calculate statistics and populate table
	(&model).calculateStats()
	(&model).populateTable()

	// Create and run the Bubble Tea program without alt screen
	p := tea.NewProgram(model)

	_, err := p.Run()
	return err
}

// GetSummary returns a text summary of the results
func (rv *ResultsViewer) GetSummary() string {
	model := NewMainModel(rv.params, rv.bom)
	model.scanDuration = rv.elapsed

	if rv.bom != nil && rv.bom.Vulnerabilities != nil {
		model.vulnCount = len(*rv.bom.Vulnerabilities)
	}

	(&model).calculateStats()

	return model.renderScanSummary()
}

// DisplayResults handles all result display functionality - replaces presenter module
func DisplayResults(params types.Parameters, elapsed float64, bom *cyclonedx.BOM) {
	if len(params.File) > 0 {
		err := helper.SaveToFile(bom, params.File, params.Format.String())
		if err != nil {
			log.Debugf("Failed to save results to file : %s", err.Error())
		}
		return
	}

	// Display the results based on format and interaction mode
	switch params.Format {
	case types.Table:
		// Table format should be non-interactive by default for proper terminal output
		displayCleanTableResults(bom, elapsed, params.Quiet)
	case types.JSON:
		// Display the results in a JSON format
		result, err := helper.ToJSON(*bom)
		if err != nil {
			log.Debug(err)
		}
		log.Print(string(result))
	}
}

func displayCleanTableResults(bom *cyclonedx.BOM, elapsed float64, quiet bool) {
	if quiet {
		return
	}

	componentCount := 0
	if bom.Components != nil {
		componentCount = len(*bom.Components)
	}

	vulnCount := 0
	if bom.Vulnerabilities != nil {
		vulnCount = len(*bom.Vulnerabilities)
	}

	// Simple, clean header
	fmt.Printf("\nJacked Security Scanner Results\n")
	fmt.Printf("===============================\n")
	fmt.Printf("Components scanned: %d\n", componentCount)
	fmt.Printf("Scan duration: %.2f seconds\n", elapsed)
	fmt.Printf("Vulnerabilities found: %d\n\n", vulnCount)

	if vulnCount == 0 {
		fmt.Println("No vulnerabilities detected.")
		return
	}

	// Use simple borderless table instead of complex Bubble Tea table
	fmt.Print(renderSimpleTable(bom))

	fmt.Printf("Scan completed in %.2f seconds\n", elapsed)
}

// renderSimpleTable creates a simple text-based table without borders for better terminal compatibility
func renderSimpleTable(bom *cyclonedx.BOM) string {
	if bom == nil || bom.Vulnerabilities == nil || bom.Components == nil {
		return "No vulnerabilities found.\n"
	}

	vulnerabilities := *bom.Vulnerabilities
	components := *bom.Components

	// Create component lookup map
	componentsMap := make(map[string]cyclonedx.Component)
	for _, c := range components {
		componentsMap[c.BOMRef] = c
	}

	// Get actual terminal width or use sensible default
	termWidth := getTerminalWidth()
	if termWidth < 60 {
		termWidth = 80 // Fallback for very small or unknown terminals
	}

	var result strings.Builder

	// Simple header with vulnerability count
	result.WriteString(fmt.Sprintf("Found %d vulnerabilities:\n\n", len(vulnerabilities)))

	// Calculate optimal column widths for terminal
	colWidths := calculateTableColumnWidths(termWidth)

	// Write table header
	writeTableHeader(&result, colWidths, termWidth)

	// Write table rows
	writeTableRows(&result, vulnerabilities, componentsMap, colWidths, termWidth)

	result.WriteString("\n")
	return result.String()
}

// calculateTableColumnWidths determines optimal column widths based on terminal size
func calculateTableColumnWidths(termWidth int) map[string]int {
	widths := make(map[string]int)

	if termWidth < 80 {
		// Narrow terminal - show only essential columns
		widths["component"] = 22
		widths["cve"] = 16
		widths["severity"] = 12
		widths["showVersion"] = 0
		widths["showDescription"] = 0
	} else {
		// Normal terminal - full table
		// Reserve space for column separators (4 spaces between 5 columns)
		availableWidth := termWidth - 8

		// Set fixed widths for consistent alignment
		widths["component"] = 24
		widths["version"] = 12
		widths["cve"] = 18
		widths["severity"] = 17 // Fine-tuned width for colored severity text

		// Remaining width for description
		usedWidth := widths["component"] + widths["version"] + widths["cve"] + widths["severity"]
		widths["description"] = availableWidth - usedWidth
		if widths["description"] < 18 {
			widths["description"] = 18
		}

		widths["showVersion"] = 1
		widths["showDescription"] = 1
	}

	return widths
}

// writeTableHeader writes the table header row
func writeTableHeader(result *strings.Builder, widths map[string]int, termWidth int) {
	if termWidth < 80 {
		// Narrow format header
		result.WriteString(fmt.Sprintf("%-*s  %-*s  %-*s\n",
			widths["component"], "COMPONENT",
			widths["cve"], "CVE",
			widths["severity"], "SEVERITY"))
		headerLen := widths["component"] + widths["cve"] + widths["severity"] + 4
		result.WriteString(strings.Repeat("-", headerLen) + "\n")
	} else {
		// Full format header
		result.WriteString(fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %-*s\n",
			widths["component"], "COMPONENT",
			widths["version"], "VERSION",
			widths["cve"], "CVE",
			widths["severity"], "SEVERITY",
			widths["description"], "FIX AVAILABLE"))
		// Calculate correct header length based on actual column widths and spacing
		headerLen := widths["component"] + widths["version"] + widths["cve"] + widths["severity"] + widths["description"] + 8
		result.WriteString(strings.Repeat("-", headerLen) + "\n")
	}
}

// writeTableRows writes the vulnerability data rows
func writeTableRows(result *strings.Builder, vulnerabilities []cyclonedx.Vulnerability, componentsMap map[string]cyclonedx.Component, widths map[string]int, termWidth int) {
	for _, vuln := range vulnerabilities {
		componentRef := getVulnComponentRef(vuln)
		component, exists := componentsMap[componentRef]
		if !exists {
			continue
		}

		// Extract and format data
		severityRaw := extractVulnSeverity(vuln)
		severityColored := applyColorToSeverity(severityRaw)
		compName := truncateToWidth(component.Name, widths["component"])

		cveId := truncateToWidth(vuln.ID, widths["cve"])

		if termWidth < 80 {
			// Narrow format row - use 2 spaces between columns for consistency
			result.WriteString(fmt.Sprintf("%-*s  %-*s  %s\n",
				widths["component"], compName,
				widths["cve"], cveId,
				severityColored)) // Don't pad colored text with printf
		} else {
			// Full format row - build string manually for better control
			version := truncateToWidth(component.Version, widths["version"])

			// Extract fix information from vulnerability
			fixInfo := extractFixInfo(vuln)
			fixInfo = truncateToWidth(fixInfo, widths["description"])

			// Build each column with proper padding
			col1 := fmt.Sprintf("%-*s", widths["component"], compName)
			col2 := fmt.Sprintf("%-*s", widths["version"], version)
			col3 := fmt.Sprintf("%-*s", widths["cve"], cveId)
			col4 := padString(severityColored, severityRaw, widths["severity"])
			col5 := fixInfo

			// Join with consistent spacing
			row := fmt.Sprintf("%s  %s  %s  %s  %s\n", col1, col2, col3, col4, col5)
			result.WriteString(row)
		}
	}
}

// Helper functions for table rendering
func getVulnComponentRef(vuln cyclonedx.Vulnerability) string {
	if vuln.Affects != nil && len(*vuln.Affects) > 0 {
		return (*vuln.Affects)[0].Ref
	}
	return vuln.BOMRef
}

func extractVulnSeverity(vuln cyclonedx.Vulnerability) string {
	// Check ratings first
	if vuln.Ratings != nil && len(*vuln.Ratings) > 0 {
		for _, rating := range *vuln.Ratings {
			if rating.Severity != "" {
				severity := strings.ToUpper(string(rating.Severity))
				return severity // Return uncolored for proper alignment
			}
		}
	}

	// For advisories without explicit severity, check if we have upgrade info
	if vuln.Recommendation != "" {
		return "UPGRADE" // Return uncolored for proper alignment
	}

	// Default for unknown severity
	return "UNKNOWN" // Return uncolored for proper alignment
}

// extractFixInfo extracts fix information from the vulnerability
func extractFixInfo(vuln cyclonedx.Vulnerability) string {
	// First check if there's a VEX recommendation
	if vuln.Recommendation != "" {
		return extractVersionFromRecommendation(vuln.Recommendation)
	}

	// Check if there are version constraints in affects
	if vuln.Affects != nil && len(*vuln.Affects) > 0 {
		return extractVersionFromAffects((*vuln.Affects)[0])
	}

	// No fix information available
	return "None"
}

// extractVersionFromRecommendation extracts version from VEX recommendation
func extractVersionFromRecommendation(recommendation string) string {
	// Extract just the version from recommendation like "Upgrade musl to 1.2.5-r1"
	if strings.Contains(recommendation, " to ") {
		parts := strings.Split(recommendation, " to ")
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	}
	return recommendation
}

// extractVersionFromAffects extracts version from affects range
func extractVersionFromAffects(affect cyclonedx.Affects) string {
	if affect.Range != nil && len(*affect.Range) > 0 {
		versionRange := (*affect.Range)[0]
		if versionRange.Range != "" {
			// Extract fixed version from range like "< 1.2.5-r1"
			if strings.HasPrefix(versionRange.Range, "< ") {
				return strings.TrimPrefix(versionRange.Range, "< ")
			}
			return versionRange.Range
		}
	}
	return "None"
}

// applyColorToSeverity applies color coding to severity levels
func applyColorToSeverity(severity string) string {
	if !shouldUseColors() {
		return severity
	}

	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return ColorCritical + severity + ColorReset
	case "HIGH":
		return ColorHigh + severity + ColorReset
	case "MEDIUM":
		return ColorMedium + severity + ColorReset
	case "LOW":
		return ColorLow + severity + ColorReset
	case "UPGRADE":
		return ColorUpgrade + severity + ColorReset
	case "ADVISORY":
		return ColorAdvisory + severity + ColorReset
	case "UNKNOWN":
		return ColorUnknown + severity + ColorReset
	default:
		return ColorUnknown + severity + ColorReset
	}
}

// shouldUseColors determines if colors should be used in output
func shouldUseColors() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

func truncateToWidth(text string, width int) string {
	if len(text) <= width {
		return text
	}
	if width <= 3 {
		return text[:width]
	}
	return text[:width-3] + "..."
}

// padString handles padding for strings that may contain ANSI color codes
func padString(coloredText, rawText string, width int) string {
	// Calculate how much padding is needed based on the raw text length
	padding := width - len(rawText)
	if padding < 0 {
		// If the raw text is longer than the width, truncate and return
		return truncateToWidth(rawText, width)
	}
	if padding == 0 {
		return coloredText
	}
	return coloredText + strings.Repeat(" ", padding)
}

// getTerminalWidth returns the current terminal width, with a fallback
func getTerminalWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width < 60 {
		// Fallback to reasonable default for small terminals
		return 80
	}
	return width
}
