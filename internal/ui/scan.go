package ui

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/analyzer"
	"github.com/carbonetes/jacked/pkg/scan"
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

// AnalyzeWithUI performs SBOM vulnerability analysis with appropriate UI based on the mode
func AnalyzeWithUI(ctx context.Context, bom *cyclonedx.BOM, params scan.Parameters, mode ScanMode) error {
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
func determineEffectiveMode(_ ScanMode, params scan.Parameters) ScanMode {
	// Force quiet mode if specified in params
	if params.Quiet {
		return ModeQuiet
	}

	// Always use non-interactive mode now
	return ModeNonInteractive
}

// runNonInteractiveScan runs the scan with basic output
func runNonInteractiveScan(bom *cyclonedx.BOM, params scan.Parameters) error {
	log.Debug("Starting non-interactive vulnerability scan")

	start := time.Now()
	analyzer.AnalyzeCDX(bom)
	duration := time.Since(start)

	vulnCount := 0
	if bom.Vulnerabilities != nil {
		vulnCount = len(*bom.Vulnerabilities)
	}

	if !params.Quiet {
		fmt.Printf("Found %d vulnerabilities (%v)\n", vulnCount, duration.Truncate(time.Millisecond))
	}

	log.Debugf("Found %d vulnerabilities in %v", vulnCount, duration)
	return nil
}

// runQuietScan runs the scan with no UI output
func runQuietScan(bom *cyclonedx.BOM) error {
	log.Debug("Starting quiet vulnerability scan")
	analyzer.AnalyzeCDX(bom)
	return nil
}

// ShowResultsWithUI displays results with appropriate UI based on mode
func ShowResultsWithUI(bom *cyclonedx.BOM, params scan.Parameters, mode ScanMode) error {
	effectiveMode := determineEffectiveMode(mode, params)

	switch effectiveMode {
	case ModeQuiet:
		// No output in quiet mode
		return nil
	default: // ModeNonInteractive
		return showBasicResults(bom)
	}
}

// showBasicResults displays basic scan results
func showBasicResults(bom *cyclonedx.BOM) error {
	if bom == nil {
		return nil
	}

	vulnCount := 0
	if bom.Vulnerabilities != nil {
		vulnCount = len(*bom.Vulnerabilities)
	}

	fmt.Printf("Scan completed. Found %d vulnerabilities.\n", vulnCount)
	return nil
}

// RunCompleteWorkflow runs the complete workflow
func RunCompleteWorkflow(ctx context.Context, params scan.Parameters, mode ScanMode) error {
	effectiveMode := determineEffectiveMode(mode, params)

	switch effectiveMode {
	case ModeQuiet:
		return runCompleteQuietWorkflow(params)
	default: // ModeNonInteractive
		return runCompleteNonInteractiveWorkflow(params)
	}
}

// runCompleteNonInteractiveWorkflow runs the complete workflow with traditional status updates
func runCompleteNonInteractiveWorkflow(params scan.Parameters) error {
	if !params.Quiet {
		fmt.Println("Starting vulnerability scan...")
	}
	return nil
}

// runCompleteQuietWorkflow runs the complete workflow silently
func runCompleteQuietWorkflow(_ scan.Parameters) error {
	log.Debug("Running quiet workflow")
	return nil
}

// GetUICapabilities returns information about UI capabilities
func GetUICapabilities() map[string]bool {
	return map[string]bool{
		"interactive": true,
		"colors":      isTerminal(),
		"tables":      true,
	}
}
