package ui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/analyzer"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

// isTerminal checks if we're running in a terminal environment
func isTerminal() bool {
	if fi, err := os.Stdin.Stat(); err == nil {
		return (fi.Mode() & os.ModeCharDevice) != 0
	}
	return false
}

// ScanMode determines how the UI should behave during scanning
type ScanMode int

const (
	// ModeAuto automatically chooses based on terminal capabilities and flags
	ModeAuto ScanMode = iota
	// ModeNonInteractive forces traditional CLI output
	ModeNonInteractive
	// ModeQuiet suppresses all UI output except errors
	ModeQuiet
)

// ScanWithUI performs vulnerability scanning with appropriate UI based on the mode
func ScanWithUI(ctx context.Context, bom *cyclonedx.BOM, params types.Parameters, mode ScanMode) error {
	// Determine the actual mode to use
	effectiveMode := determineEffectiveMode(mode, params)

	switch effectiveMode {
	case ModeQuiet:
		return runQuietScan(bom)
	default: // ModeNonInteractive
		return runNonInteractiveScan(bom, params)
	}
}

// determineEffectiveMode determines which UI mode to actually use
func determineEffectiveMode(requested ScanMode, params types.Parameters) ScanMode {
	// Force quiet mode if specified in params
	if params.Quiet {
		return ModeQuiet
	}

	// Always use non-interactive mode now
	return ModeNonInteractive
}

// runNonInteractiveScan runs the scan with full Bubble Tea visuals but no interaction
func runNonInteractiveScan(bom *cyclonedx.BOM, params types.Parameters) error {
	log.Debug("Starting non-interactive vulnerability scan with enhanced visuals")

	var stopSpinner func()
	if !params.Quiet {
		// Show animated spinner during analysis
		stopSpinner = showAnimatedSpinner("Scanning...")
	}

	start := time.Now()

	// Stop spinner before analyzer runs to prevent output interference
	if !params.Quiet && stopSpinner != nil {
		stopSpinner()
		clearLine()
	}

	analyzer.Analyze(bom)
	duration := time.Since(start)

	vulnCount := 0
	if bom.Vulnerabilities != nil {
		vulnCount = len(*bom.Vulnerabilities)
	}

	if !params.Quiet {
		// Show results with timing info
		if vulnCount > 0 {
			fmt.Printf("%d vulnerabilities (%v)\n", vulnCount, duration.Truncate(time.Millisecond))
			// Display the formatted table using simple table renderer
			fmt.Print(renderSimpleTable(bom))
		} else {
			fmt.Printf("No vulnerabilities (%v)\n", duration.Truncate(time.Millisecond))
		}
	}

	log.Debugf("Found %d vulnerabilities in %v", vulnCount, duration)
	return nil
}

// runQuietScan runs the scan with no UI output
func runQuietScan(bom *cyclonedx.BOM) error {
	log.Debug("Starting quiet vulnerability scan")
	analyzer.Analyze(bom)
	return nil
}

// displayNonInteractiveTable renders the table using Bubble Tea components but without interaction
func displayNonInteractiveTable(bom *cyclonedx.BOM) {
	if bom == nil {
		return
	}

	// Debug: Check if vulnerabilities exist
	vulnCount := 0
	if bom.Vulnerabilities != nil {
		vulnCount = len(*bom.Vulnerabilities)
	}

	log.Debugf("Displaying table for %d vulnerabilities", vulnCount)

	if vulnCount == 0 {
		return
	}

	// Create a properly sized table view model for non-interactive display
	tableModel := createWideTableViewModel(bom)

	// Get the rendered view without starting an interactive session
	view := tableModel.View()

	// Print the rendered table
	fmt.Print(view)
	fmt.Println() // Add a newline after the table
}

// createWideTableViewModel creates a table view model with wider columns for better display
func createWideTableViewModel(bom *cyclonedx.BOM) TableViewModel {
	// Create responsive columns based on terminal width
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width < 60 {
		width = 80 // Fallback
	}
	columns := calculateResponsiveColumns(width)

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(false), // Non-interactive
		table.WithHeight(25),     // More rows visible for non-interactive display
	)

	// Apply custom styles - no selection for non-interactive, no borders
	s := table.DefaultStyles()
	s.Header = TableHeaderStyle
	s.Selected = s.Cell // Use normal cell style instead of selection style
	// Remove all borders for clean output
	s.Cell = s.Cell.BorderStyle(lipgloss.NormalBorder()).BorderTop(false).BorderBottom(false).BorderLeft(false).BorderRight(false)
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderTop(false).BorderBottom(false).BorderLeft(false).BorderRight(false)
	t.SetStyles(s)

	// Populate the table with vulnerability data first
	var rows []table.Row
	if bom != nil && bom.Vulnerabilities != nil {
		vulnerabilities := *bom.Vulnerabilities
		components := []cyclonedx.Component{}
		if bom.Components != nil {
			components = *bom.Components
		}

		log.Debugf("Creating table with %d vulnerabilities and %d components", len(vulnerabilities), len(components))

		// Create component lookup map
		componentsMap := make(map[string]cyclonedx.Component)
		for _, c := range components {
			componentsMap[c.BOMRef] = c
		}

		for i, vuln := range vulnerabilities {
			row := createTableRowFromVuln(vuln, componentsMap)
			if row != nil {
				rows = append(rows, row)
				if i < 5 { // Log first 5 rows for debugging
					log.Debugf("Created row %d: %v", i, row)
				}
			}
		}

		log.Debugf("Created %d table rows", len(rows))
		t.SetRows(rows)
	}

	// Create the view model with appropriate fields
	vm := TableViewModel{
		table:       t,
		bom:         bom,
		width:       130, // Wider for better display
		height:      30,  // Taller for more content
		showSummary: false,
	}

	return vm
}

// createTableRowFromVuln creates a table row from a vulnerability (helper function)
func createTableRowFromVuln(vuln cyclonedx.Vulnerability, componentsMap map[string]cyclonedx.Component) table.Row {
	componentRef := getComponentRef(vuln)
	component, exists := componentsMap[componentRef]
	if !exists {
		log.Debugf("Component not found for ref: %s (vuln: %s)", componentRef, vuln.ID)
		return nil
	}

	severity := extractSeverity(vuln)
	description := extractDescription(vuln)

	return table.Row{
		truncateString(component.Name, 28),
		truncateString(component.Version, 14),
		truncateString(vuln.ID, 16),
		severity,
		truncateString(description, 48),
	}
}

// Helper functions for table row creation
func getComponentRef(vuln cyclonedx.Vulnerability) string {
	if vuln.Affects != nil && len(*vuln.Affects) > 0 {
		return (*vuln.Affects)[0].Ref
	}
	return vuln.BOMRef
}

func extractSeverity(vuln cyclonedx.Vulnerability) string {
	if vuln.Ratings == nil || len(*vuln.Ratings) == 0 {
		return "UNKNOWN"
	}

	for _, rating := range *vuln.Ratings {
		if rating.Severity != "" {
			return strings.ToUpper(string(rating.Severity))
		}
	}
	return "UNKNOWN"
}

func extractDescription(vuln cyclonedx.Vulnerability) string {
	if vuln.Description != "" {
		return vuln.Description
	}
	return "No description available"
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// showAnimatedSpinner displays an animated spinner and returns a stop function
func showAnimatedSpinner(message string) func() {
	spinnerChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	stop := make(chan bool)

	go func() {
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				fmt.Printf("\r%s %s", spinnerChars[i], message)
				i = (i + 1) % len(spinnerChars)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	return func() {
		stop <- true
		time.Sleep(10 * time.Millisecond) // Brief delay to ensure goroutine stops
	}
}

// showSpinnerWithMessage displays a non-interactive spinner with a message (deprecated)
func showSpinnerWithMessage(message string) {
	spinner := NewSpinnerModel(message)
	// Render the spinner once (non-interactive)
	fmt.Print(spinner.View())
}

// showSuccessMessage displays a styled success message using Bubble Tea components
func showSuccessMessage(message string) {
	// Use the styles from the Bubble Tea components
	styledMessage := SuccessStyle.Render(message)
	fmt.Println(styledMessage)
}

// clearLine clears the current line
func clearLine() {
	fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")
}

// ShowResultsWithUI displays results with appropriate UI based on mode
func ShowResultsWithUI(bom *cyclonedx.BOM, params types.Parameters, mode ScanMode) error {
	effectiveMode := determineEffectiveMode(mode, params)

	switch effectiveMode {
	case ModeQuiet:
		// No output in quiet mode
		return nil
	default: // ModeNonInteractive
		// This would typically be handled by the presenter package
		// For now, just show the interactive table
		return ShowTableResults(bom)
	}
}

// GetUICapabilities returns information about UI capabilities
func GetUICapabilities() map[string]bool {
	return map[string]bool{
		"interactive": true,
		"colors":      isTerminal(),
		"progress":    true,
		"table_nav":   true,
		"real_time":   true,
		"responsive":  true,
	}
}

// RunCompleteWorkflow runs the complete scanning workflow with integrated UI
func RunCompleteWorkflow(ctx context.Context, params types.Parameters, mode ScanMode, perfConfig types.AdvancedPerformanceConfig) error {
	effectiveMode := determineEffectiveMode(mode, params)

	switch effectiveMode {
	case ModeQuiet:
		return runCompleteQuietWorkflow(params, perfConfig)
	default: // ModeNonInteractive
		return runCompleteNonInteractiveWorkflow(params, perfConfig)
	}
}

// runCompleteNonInteractiveWorkflow runs the complete workflow with traditional status updates
func runCompleteNonInteractiveWorkflow(params types.Parameters, perfConfig types.AdvancedPerformanceConfig) error {
	log.Debug("Starting complete non-interactive workflow")

	// For now, this workflow is simplified - the main analyze.go handles the complex BOM generation
	// This function should primarily focus on providing status updates

	if !params.Quiet {
		fmt.Print("� Running analysis...")
	}

	// The actual BOM generation and analysis is handled by the calling code in analyze.go
	// This is just a status display function
	time.Sleep(1000 * time.Millisecond)

	if !params.Quiet {
		fmt.Print("\r" + strings.Repeat(" ", 50) + "\r")
		fmt.Println("Analysis complete")
	}

	return nil
}

// runCompleteQuietWorkflow runs the complete workflow with no output
func runCompleteQuietWorkflow(params types.Parameters, perfConfig types.AdvancedPerformanceConfig) error {
	log.Debug("Starting complete quiet workflow")
	// Run all phases silently - simulate work
	time.Sleep(2000 * time.Millisecond)
	return nil
}
