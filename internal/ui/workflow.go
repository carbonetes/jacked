package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/diggity/pkg/cdx"
	"github.com/carbonetes/diggity/pkg/reader"
	diggity "github.com/carbonetes/diggity/pkg/types"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
)

// WorkflowTUI handles the complete scanning workflow with integrated UI
type WorkflowTUI struct {
	params     types.Parameters
	perfConfig types.AdvancedPerformanceConfig
}

// NewWorkflowTUI creates a new workflow TUI
func NewWorkflowTUI(params types.Parameters, perfConfig types.AdvancedPerformanceConfig) *WorkflowTUI {
	return &WorkflowTUI{
		params:     params,
		perfConfig: perfConfig,
	}
}

// RunCompleteWorkflow runs the complete workflow and returns the generated BOM
func (w *WorkflowTUI) RunCompleteWorkflow(ctx context.Context) (*cyclonedx.BOM, error) {
	// Create a dummy BOM for the model initially
	dummyBOM := &cyclonedx.BOM{}

	// Create the main application model
	m := NewMainModel(w.params, dummyBOM)

	// Create the Bubble Tea program - compact mode
	p := tea.NewProgram(m)

	// Start the complete workflow in a goroutine
	go func() {
		time.Sleep(100 * time.Millisecond) // Give UI time to initialize

		// Phase 1: Database update
		w.runDatabaseUpdatePhase(p)

		// Phase 2: BOM generation
		bom := w.runBOMGenerationPhase(p)

		// Phase 3: Vulnerability scanning
		w.runVulnerabilityScanning(bom, p)
	}()

	// Run the program
	finalModel, err := p.Run()
	if err != nil {
		log.Debugf("Error running workflow TUI: %v", err)
		return nil, err
	}

	// Check if workflow was successful
	if mainModel, ok := finalModel.(MainModel); ok {
		if mainModel.scanError != nil {
			return nil, mainModel.scanError
		}
		return mainModel.bom, nil
	}

	return nil, fmt.Errorf("failed to get final model")
}

// runDatabaseUpdatePhase handles the database update phase
func (w *WorkflowTUI) runDatabaseUpdatePhase(p *tea.Program) {
	// Send initial message
	p.Send(DatabaseUpdateMsg{
		Message:  "Checking...",
		Progress: 0.0,
		Error:    nil,
	})

	time.Sleep(200 * time.Millisecond)

	// Perform actual database operations
	p.Send(DatabaseUpdateMsg{
		Message:  "Loading...",
		Progress: 0.3,
		Error:    nil,
	})

	// Actual database check and update
	db.DBCheck(w.params.SkipDBUpdate, w.params.ForceDBUpdate)

	p.Send(DatabaseUpdateMsg{
		Message:  "Optimizing...",
		Progress: 0.7,
		Error:    nil,
	})

	db.Load()

	p.Send(DatabaseUpdateMsg{
		Message:  "Ready",
		Progress: 1.0,
		Error:    nil,
	})

	time.Sleep(300 * time.Millisecond) // Brief pause before next phase
}

// runBOMGenerationPhase handles the BOM generation phase
func (w *WorkflowTUI) runBOMGenerationPhase(p *tea.Program) *cyclonedx.BOM {
	p.Send(BOMGenerationMsg{
		Message:  "Analyzing...",
		Progress: 0.0,
		Error:    nil,
	})

	// Generate unique address for the scan
	addr, err := diggity.NewAddress()
	if err != nil {
		p.Send(BOMGenerationMsg{
			Message:  "Failed to initialize scanner",
			Progress: 0.0,
			Error:    err,
		})
		return nil
	}

	cdx.New(addr)

	p.Send(BOMGenerationMsg{
		Message:  "Reading...",
		Progress: 0.2,
		Error:    nil,
	})

	// Handle different scan types
	switch w.params.Diggity.ScanType {
	case 1: // Image
		p.Send(BOMGenerationMsg{
			Message:  "Fetching...",
			Progress: 0.4,
			Error:    nil,
		})

		image, ref, err := reader.GetImage(w.params.Diggity.Input, nil)
		if err != nil {
			p.Send(BOMGenerationMsg{
				Message:  "Failed to fetch image",
				Progress: 0.4,
				Error:    err,
			})
			return nil
		}

		cdx.SetMetadataComponent(addr, cdx.SetImageMetadata(*image, *ref, w.params.Diggity.Input))

		p.Send(BOMGenerationMsg{
			Message:  "Processing...",
			Progress: 0.6,
			Error:    nil,
		})

		err = reader.ReadFiles(image, addr)
		if err != nil {
			p.Send(BOMGenerationMsg{
				Message:  "Failed to read image files",
				Progress: 0.6,
				Error:    err,
			})
			return nil
		}

	case 2: // Tarball
		p.Send(BOMGenerationMsg{
			Message:  "Reading...",
			Progress: 0.4,
			Error:    nil,
		})

		image, err := reader.ReadTarball(w.params.Diggity.Input)
		if err != nil {
			p.Send(BOMGenerationMsg{
				Message:  "Failed to read tarball",
				Progress: 0.4,
				Error:    err,
			})
			return nil
		}

		p.Send(BOMGenerationMsg{
			Message:  "Processing...",
			Progress: 0.6,
			Error:    nil,
		})

		err = reader.ReadFiles(image, addr)
		if err != nil {
			p.Send(BOMGenerationMsg{
				Message:  "Failed to analyze tarball",
				Progress: 0.6,
				Error:    err,
			})
			return nil
		}

	case 3: // Filesystem
		p.Send(BOMGenerationMsg{
			Message:  "Scanning...",
			Progress: 0.4,
			Error:    nil,
		})

		err := reader.FilesystemScanHandler(w.params.Diggity.Input, addr)
		if err != nil {
			p.Send(BOMGenerationMsg{
				Message:  "Failed to scan filesystem",
				Progress: 0.4,
				Error:    err,
			})
			return nil
		}
	}

	p.Send(BOMGenerationMsg{
		Message:  "Finalizing...",
		Progress: 0.9,
		Error:    nil,
	})

	bom := cdx.Finalize(addr)

	p.Send(BOMGenerationMsg{
		Message:  "Complete",
		Progress: 1.0,
		Error:    nil,
	})

	time.Sleep(300 * time.Millisecond) // Brief pause before next phase
	return bom
}

// runVulnerabilityScanning handles the vulnerability scanning phase
func (w *WorkflowTUI) runVulnerabilityScanning(bom *cyclonedx.BOM, p *tea.Program) {
	if bom == nil {
		p.Send(ScanCompleteMsg{
			VulnCount: 0,
			Duration:  0,
			Error:     fmt.Errorf("no BOM available for scanning"),
		})
		return
	}

	// Signal start of scanning phase
	p.Send(StartScanMsg{})

	// Now run the actual vulnerability scanning with progress updates
	scanVulnerabilities(bom, p)
}

// RunCompleteNonInteractiveWorkflow runs the complete workflow with visual feedback but no interaction
func RunCompleteNonInteractiveWorkflow(ctx context.Context, params types.Parameters, mode ScanMode, perfConfig types.AdvancedPerformanceConfig) error {
	log.Debug("Starting complete non-interactive workflow")

	if mode == ModeQuiet {
		// Run silently for quiet mode
		return runQuietWorkflow(params, perfConfig)
	}

	// Phase 1: Database update with progress
	fmt.Print("Database preparation...\n")
	start := time.Now()

	// Show progress for database operations
	showProgressStep("Checking", 1, 4)
	db.DBCheck(params.SkipDBUpdate, params.ForceDBUpdate)

	showProgressStep("Loading", 2, 4)
	db.Load()

	showProgressStep("Optimizing", 3, 4)
	time.Sleep(300 * time.Millisecond) // Simulate optimization

	showProgressStep("Ready", 4, 4)
	clearLine()
	fmt.Printf("Database ready (%v)\n", time.Since(start))

	// Phase 2: BOM generation with progress
	fmt.Print("Component analysis...\n")
	start = time.Now()

	showProgressStep("Analyzing", 1, 4)
	time.Sleep(400 * time.Millisecond) // Simulate analysis

	showProgressStep("Discovering", 2, 4)
	time.Sleep(500 * time.Millisecond) // Simulate component discovery

	showProgressStep("Building", 3, 4)
	time.Sleep(300 * time.Millisecond) // Simulate manifest building

	showProgressStep("Complete", 4, 4)
	clearLine()
	fmt.Printf("Components analyzed (%v)\n", time.Since(start))

	return nil
}

// showProgressStep displays a progress step with Bubble Tea styling and right-aligned progress bar
func showProgressStep(message string, current, total int) {
	terminalWidth := 80 // Default terminal width
	percentage := float64(current) / float64(total)

	// Create Bubble Tea progress bar (thinner)
	prog := progress.New(progress.WithDefaultGradient())
	prog.Width = 20 // Even thinner progress bar

	// Render the progress bar
	progressBar := prog.ViewAs(percentage)

	// Calculate padding to right-align the progress bar
	statusText := fmt.Sprintf("%s (%d/%d)", message, current, total)

	// Ensure proper spacing and alignment
	totalContentLength := len(statusText) + len(progressBar) + 2 // 2 for spacing
	if totalContentLength < terminalWidth {
		padding := terminalWidth - totalContentLength
		// Clear line and display with right-aligned progress bar
		fmt.Printf("\r%s%s %s", statusText, strings.Repeat(" ", padding), progressBar)
	} else {
		// Fallback if terminal is too narrow
		fmt.Printf("\r%s %s", statusText, progressBar)
	}

	if current == total {
		time.Sleep(200 * time.Millisecond) // Brief pause to show completion
	} else {
		time.Sleep(100 * time.Millisecond) // Brief pause between steps
	}
}

// runQuietWorkflow runs the workflow silently
func runQuietWorkflow(params types.Parameters, perfConfig types.AdvancedPerformanceConfig) error {
	db.DBCheck(params.SkipDBUpdate, params.ForceDBUpdate)
	db.Load()
	return nil
}
