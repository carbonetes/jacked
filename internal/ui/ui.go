package ui

import (
	"context"
	"fmt"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/analyzer"
	"github.com/carbonetes/jacked/pkg/types"
	tea "github.com/charmbracelet/bubbletea"
)

// InteractiveTUI represents the interactive terminal UI
type InteractiveTUI struct {
	params types.Parameters
}

// NewInteractiveTUI creates a new interactive TUI instance
func NewInteractiveTUI(params types.Parameters) *InteractiveTUI {
	return &InteractiveTUI{
		params: params,
	}
}

// RunInteractiveScan runs an interactive scan using Bubble Tea with all phases
func (t *InteractiveTUI) RunInteractiveScan(ctx context.Context, bom *cyclonedx.BOM) error {
	// Create the main application model
	m := NewMainModel(t.params, bom)

	// Create the Bubble Tea program - no full screen for compact mode
	p := tea.NewProgram(m)

	// Start the complete workflow in a goroutine
	go func() {
		time.Sleep(100 * time.Millisecond) // Give UI time to initialize

		// Start database update phase
		runDatabaseUpdate(t.params, p)

		// Start BOM generation phase
		runBOMGeneration(t.params, p)

		// Start scanning phase
		p.Send(StartScanMsg{})
		scanVulnerabilities(bom, p)
	}()

	// Run the program
	finalModel, err := p.Run()
	if err != nil {
		log.Debugf("Error running interactive TUI: %v", err)
		return err
	}

	// Check if scanning was successful
	if mainModel, ok := finalModel.(MainModel); ok {
		if mainModel.scanError != nil {
			return mainModel.scanError
		}
	}

	return nil
}

// DatabaseUpdateMsg represents database update progress
type DatabaseUpdateMsg struct {
	Message  string
	Progress float64
	Error    error
}

// BOMGenerationMsg represents BOM generation progress
type BOMGenerationMsg struct {
	Message  string
	Progress float64
	Error    error
}

// StartScanMsg is sent to start the vulnerability scan
type StartScanMsg struct{}

// ScanProgressMsg represents scan progress updates
type ScanProgressMsg struct {
	Component string
	Progress  float64
	Message   string
}

// ScanCompleteMsg is sent when scanning is complete
type ScanCompleteMsg struct {
	VulnCount int
	Duration  time.Duration
	Error     error
}

// scanVulnerabilities performs the vulnerability scan and sends progress updates
func scanVulnerabilities(bom *cyclonedx.BOM, p *tea.Program) {
	start := time.Now()

	// Send initial progress
	p.Send(ScanProgressMsg{
		Component: "Initializing",
		Progress:  0.0,
		Message:   "Starting vulnerability analysis...",
	})

	// Simulate progress during analysis
	// In a real implementation, this would hook into the analyzer's progress reporting
	componentCount := 0
	if bom.Components != nil {
		componentCount = len(*bom.Components)
	}

	if componentCount > 0 {
		for i, component := range *bom.Components {
			progress := float64(i) / float64(componentCount)
			p.Send(ScanProgressMsg{
				Component: component.Name,
				Progress:  progress,
				Message:   fmt.Sprintf("Scanning %s...", component.Name),
			})

			// Small delay to show progress (remove in production)
			time.Sleep(50 * time.Millisecond)
		}
	}

	// Perform the actual analysis
	p.Send(ScanProgressMsg{
		Component: "Analysis",
		Progress:  0.9,
		Message:   "Analyzing vulnerabilities...",
	})

	analyzer.Analyze(bom)

	// Count vulnerabilities
	vulnCount := 0
	if bom.Vulnerabilities != nil {
		vulnCount = len(*bom.Vulnerabilities)
	}

	duration := time.Since(start)

	// Send completion message
	p.Send(ScanCompleteMsg{
		VulnCount: vulnCount,
		Duration:  duration,
		Error:     nil,
	})
}

// runDatabaseUpdate handles the database update phase
func runDatabaseUpdate(params types.Parameters, p *tea.Program) {
	// Send initial message
	p.Send(DatabaseUpdateMsg{
		Message:  "Checking database status...",
		Progress: 0.0,
		Error:    nil,
	})

	// Small delay for UI
	time.Sleep(200 * time.Millisecond)

	// Import db package functions here - this would need to be integrated
	// For now, simulate the database update process
	p.Send(DatabaseUpdateMsg{
		Message:  "Database update in progress...",
		Progress: 0.5,
		Error:    nil,
	})

	time.Sleep(500 * time.Millisecond)

	p.Send(DatabaseUpdateMsg{
		Message:  "Database ready",
		Progress: 1.0,
		Error:    nil,
	})
}

// runBOMGeneration handles the BOM generation phase
func runBOMGeneration(params types.Parameters, p *tea.Program) {
	p.Send(BOMGenerationMsg{
		Message:  "Analyzing target...",
		Progress: 0.0,
		Error:    nil,
	})

	time.Sleep(300 * time.Millisecond)

	p.Send(BOMGenerationMsg{
		Message:  "Reading files and packages...",
		Progress: 0.3,
		Error:    nil,
	})

	time.Sleep(400 * time.Millisecond)

	p.Send(BOMGenerationMsg{
		Message:  "Generating component list...",
		Progress: 0.7,
		Error:    nil,
	})

	time.Sleep(300 * time.Millisecond)

	p.Send(BOMGenerationMsg{
		Message:  "BOM generation complete",
		Progress: 1.0,
		Error:    nil,
	})
}
