package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
)

// ViewState represents the current view state
type ViewState int

const (
	ViewDatabaseUpdate ViewState = iota
	ViewBOMGeneration
	ViewScanning
	ViewResults
	ViewDetailedResults
	ViewError
	ViewHelp
)

// MainModel represents the main application model
type MainModel struct {
	params           types.Parameters
	bom              *cyclonedx.BOM
	state            ViewState
	progress         progress.Model
	table            table.Model
	scanError        error
	vulnCount        int
	scanDuration     time.Duration
	currentMessage   string
	currentComponent string
	width            int
	height           int
	selectedIndex    int
	showDetails      bool
	filterSeverity   string
	sortBy           string
	stats            ScanStats
}

// ScanStats holds scanning statistics
type ScanStats struct {
	TotalComponents   int
	ScannedComponents int
	CriticalVulns     int
	HighVulns         int
	MediumVulns       int
	LowVulns          int
	NegligibleVulns   int
	DatabaseSize      string
	LastDBUpdate      time.Time
	ScanStartTime     time.Time
	ComponentsPerSec  float64
}

// NewMainModel creates a new main model
func NewMainModel(params types.Parameters, bom *cyclonedx.BOM) MainModel {
	// Initialize progress bar with enhanced styling
	prog := progress.New(progress.WithDefaultGradient())
	prog.Width = 50 // Wider progress bar
	prog.ShowPercentage = true

	// Initialize enhanced table
	columns := []table.Column{
		{Title: "📦 Component", Width: 25},
		{Title: "📋 Version", Width: 15},
		{Title: "🔍 CVE", Width: 18},
		{Title: "⚠️  Severity", Width: 12},
		{Title: "📝 Description", Width: 40},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(12), // Larger table height
	)

	s := table.DefaultStyles()
	s.Header = TableHeaderStyle
	s.Selected = TableSelectedStyle
	t.SetStyles(s)

	return MainModel{
		params:         params,
		bom:            bom,
		state:          ViewDatabaseUpdate,
		progress:       prog,
		table:          t,
		width:          120,
		height:         40,
		selectedIndex:  0,
		showDetails:    false,
		filterSeverity: "",
		sortBy:         "severity",
		stats: ScanStats{
			ScanStartTime: time.Now(),
		},
	}
}

// Init initializes the model
func (m MainModel) Init() tea.Cmd {
	return nil
}

// Update handles messages and updates the model
func (m MainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		return m.handleWindowResize(msg)
	case tea.KeyMsg:
		return m.handleKeyPress(msg)
	case StartScanMsg:
		return m.handleStartScan(msg)
	case DatabaseUpdateMsg:
		return m.handleDatabaseUpdate(msg)
	case BOMGenerationMsg:
		return m.handleBOMGeneration(msg)
	case ScanProgressMsg:
		return m.handleScanProgress(msg)
	case ScanCompleteMsg:
		return m.handleScanComplete(msg)
	case progress.FrameMsg:
		return m.handleProgressFrame(msg)
	}

	// Update table if in results view
	if m.state == ViewResults || m.state == ViewDetailedResults {
		var cmd tea.Cmd
		m.table, cmd = m.table.Update(msg)
		return m, cmd
	}

	return m, nil
}

// handleWindowResize handles window resize events
func (m MainModel) handleWindowResize(msg tea.WindowSizeMsg) (tea.Model, tea.Cmd) {
	m.width = min(msg.Width, 120)            // Larger max width
	m.height = min(msg.Height, 40)           // Larger max height
	m.progress.Width = min(msg.Width-10, 50) // Wider progress bar
	return m, nil
}

// handleKeyPress handles keyboard input
func (m MainModel) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "enter", " ":
		return m.handleEnterKey()
	case "d":
		return m.handleDetailKey()
	case "r":
		return m.handleReturnKey()
	case "h", "?":
		return m.handleHelpKey()
	case "esc":
		return m.handleEscapeKey()
	case "1", "2", "3", "4", "5":
		return m.handleSeverityFilter(key)
	}
	return m, nil
}

// handleEnterKey handles enter key press
func (m MainModel) handleEnterKey() (tea.Model, tea.Cmd) {
	if m.state == ViewResults || m.state == ViewError {
		return m, tea.Quit
	}
	return m, nil
}

// handleDetailKey handles detail view key press
func (m MainModel) handleDetailKey() (tea.Model, tea.Cmd) {
	if m.state == ViewResults {
		m.state = ViewDetailedResults
		m.showDetails = true
	}
	return m, nil
}

// handleReturnKey handles return to main view key press
func (m MainModel) handleReturnKey() (tea.Model, tea.Cmd) {
	if m.state == ViewDetailedResults {
		m.state = ViewResults
		m.showDetails = false
	}
	return m, nil
}

// handleHelpKey handles help key press
func (m MainModel) handleHelpKey() (tea.Model, tea.Cmd) {
	if m.state == ViewResults || m.state == ViewDetailedResults {
		m.state = ViewHelp
	}
	return m, nil
}

// handleEscapeKey handles escape key press
func (m MainModel) handleEscapeKey() (tea.Model, tea.Cmd) {
	if m.state == ViewHelp {
		if m.showDetails {
			m.state = ViewDetailedResults
		} else {
			m.state = ViewResults
		}
	}
	return m, nil
}

// handleSeverityFilter handles severity filter key press
func (m MainModel) handleSeverityFilter(key string) (tea.Model, tea.Cmd) {
	if m.state == ViewResults || m.state == ViewDetailedResults {
		severities := []string{"", "CRITICAL", "HIGH", "MEDIUM", "LOW"}
		if idx := int(key[0] - '0'); idx < len(severities) {
			m.filterSeverity = severities[idx]
			m.populateTable()
		}
	}
	return m, nil
}

// handleStartScan handles scan start message
func (m MainModel) handleStartScan(msg StartScanMsg) (tea.Model, tea.Cmd) {
	m.state = ViewScanning
	return m, nil
}

// handleDatabaseUpdate handles database update messages
func (m MainModel) handleDatabaseUpdate(msg DatabaseUpdateMsg) (tea.Model, tea.Cmd) {
	if msg.Error != nil {
		m.scanError = msg.Error
		m.state = ViewError
	} else {
		m.currentMessage = msg.Message
		if msg.Progress >= 1.0 {
			m.state = ViewBOMGeneration
		}
	}
	return m, m.progress.SetPercent(msg.Progress)
}

// handleBOMGeneration handles BOM generation messages
func (m MainModel) handleBOMGeneration(msg BOMGenerationMsg) (tea.Model, tea.Cmd) {
	if msg.Error != nil {
		m.scanError = msg.Error
		m.state = ViewError
	} else {
		m.currentMessage = msg.Message
		if msg.Progress >= 1.0 {
			m.state = ViewScanning
		}
	}
	return m, m.progress.SetPercent(msg.Progress)
}

// handleScanProgress handles scan progress messages
func (m MainModel) handleScanProgress(msg ScanProgressMsg) (tea.Model, tea.Cmd) {
	m.currentMessage = msg.Message
	m.currentComponent = msg.Component
	m.stats.ScannedComponents++

	// Calculate scanning speed
	elapsed := time.Since(m.stats.ScanStartTime).Seconds()
	if elapsed > 0 {
		m.stats.ComponentsPerSec = float64(m.stats.ScannedComponents) / elapsed
	}

	return m, m.progress.SetPercent(msg.Progress)
}

// handleScanComplete handles scan completion messages
func (m MainModel) handleScanComplete(msg ScanCompleteMsg) (tea.Model, tea.Cmd) {
	if msg.Error != nil {
		m.scanError = msg.Error
		m.state = ViewError
	} else {
		m.vulnCount = msg.VulnCount
		m.scanDuration = msg.Duration
		m.state = ViewResults
		m.calculateStats()
		m.populateTable()
	}
	return m, nil
}

// handleProgressFrame handles progress bar frame updates
func (m MainModel) handleProgressFrame(msg progress.FrameMsg) (tea.Model, tea.Cmd) {
	progressModel, cmd := m.progress.Update(msg)
	m.progress = progressModel.(progress.Model)
	return m, cmd
}

// View renders the current view
func (m MainModel) View() string {
	switch m.state {
	case ViewDatabaseUpdate:
		return m.renderDatabaseUpdateView()
	case ViewBOMGeneration:
		return m.renderBOMGenerationView()
	case ViewScanning:
		return m.renderScanningView()
	case ViewResults:
		return m.renderResultsView()
	case ViewDetailedResults:
		return m.renderDetailedResultsView()
	case ViewHelp:
		return m.renderHelpView()
	case ViewError:
		return m.renderErrorView()
	default:
		return "Unknown view"
	}
}

// renderScanningView renders the enhanced scanning progress view
func (m MainModel) renderScanningView() string {
	var parts []string

	// Header with branding
	header := HeaderStyle.Render("🔍 Jacked Security Scanner")
	parts = append(parts, header)

	// Current status
	if m.currentMessage != "" {
		status := InfoStyle.Render(fmt.Sprintf("Status: %s", m.currentMessage))
		parts = append(parts, status)
	}

	// Current component being scanned
	if m.currentComponent != "" {
		component := MutedStyle.Render(fmt.Sprintf("Scanning: %s", m.currentComponent))
		parts = append(parts, component)
	}

	// Progress bar with percentage
	progressInfo := fmt.Sprintf("Progress: %s", m.progress.View())
	parts = append(parts, progressInfo)

	// Statistics if available
	if m.stats.ScannedComponents > 0 {
		speed := fmt.Sprintf("Speed: %.1f components/sec", m.stats.ComponentsPerSec)
		scanTime := time.Since(m.stats.ScanStartTime)
		timeInfo := fmt.Sprintf("Elapsed: %v", scanTime.Truncate(time.Second))
		stats := MutedStyle.Render(fmt.Sprintf("%s | %s", speed, timeInfo))
		parts = append(parts, stats)
	}

	return Box(strings.Join(parts, "\n"), "Vulnerability Scanning")
}

// renderResultsView renders the enhanced results table view
func (m MainModel) renderResultsView() string {
	var content strings.Builder

	// Header with scan summary
	header := m.renderScanSummary()
	content.WriteString(header)
	content.WriteString("\n")

	// Vulnerability statistics
	if m.vulnCount > 0 {
		stats := m.renderVulnerabilityStats()
		content.WriteString(stats)
		content.WriteString("\n")

		// Table with vulnerabilities
		content.WriteString(TitleStyle.Render("📋 Vulnerability Details"))
		content.WriteString("\n")
		content.WriteString(m.table.View())
		content.WriteString("\n")

		// Controls help
		controls := m.renderControlsHelp()
		content.WriteString(controls)
	} else {
		// No vulnerabilities found
		successMsg := SuccessBox("No vulnerabilities found! Your scan is clean.", "✅ All Clear")
		content.WriteString(successMsg)
	}

	return content.String()
}

// renderScanSummary renders the scan summary information
func (m MainModel) renderScanSummary() string {
	var parts []string

	// Scan duration and component count
	duration := fmt.Sprintf("Scan completed in %v", m.scanDuration.Truncate(time.Millisecond))
	parts = append(parts, duration)

	if m.stats.TotalComponents > 0 {
		compInfo := fmt.Sprintf("%d components analyzed", m.stats.TotalComponents)
		parts = append(parts, compInfo)
	}

	summary := strings.Join(parts, " • ")

	if m.vulnCount > 0 {
		title := fmt.Sprintf("🚨 Security Scan Results - %d Vulnerabilities Found", m.vulnCount)
		return Box(summary, title)
	} else {
		title := "✅ Security Scan Results - No Vulnerabilities"
		return SuccessBox(summary, title)
	}
}

// renderVulnerabilityStats renders vulnerability statistics
func (m MainModel) renderVulnerabilityStats() string {
	var statsCards []string

	if m.stats.CriticalVulns > 0 {
		card := StatCard("Critical", fmt.Sprintf("%d", m.stats.CriticalVulns), "Immediate action required")
		statsCards = append(statsCards, card)
	}
	if m.stats.HighVulns > 0 {
		card := StatCard("High", fmt.Sprintf("%d", m.stats.HighVulns), "Should be addressed soon")
		statsCards = append(statsCards, card)
	}
	if m.stats.MediumVulns > 0 {
		card := StatCard("Medium", fmt.Sprintf("%d", m.stats.MediumVulns), "Schedule for fix")
		statsCards = append(statsCards, card)
	}
	if m.stats.LowVulns > 0 {
		card := StatCard("Low", fmt.Sprintf("%d", m.stats.LowVulns), "Low priority")
		statsCards = append(statsCards, card)
	}

	if len(statsCards) == 0 {
		return ""
	}

	return strings.Join(statsCards, " ")
}

// renderControlsHelp renders the controls help
func (m MainModel) renderControlsHelp() string {
	controls := []string{
		"↑/↓ navigate",
		"d details",
		"h help",
		"1-5 filter by severity",
		"q quit",
	}

	helpText := strings.Join(controls, " • ")
	return HelpStyle.Render(helpText)
}

// renderErrorView renders the enhanced error view
func (m MainModel) renderErrorView() string {
	var errorMsg string
	if m.scanError != nil {
		errorMsg = fmt.Sprintf("An error occurred during scanning:\n%v", m.scanError)
	} else {
		errorMsg = "An unknown error occurred during scanning."
	}

	help := "Press 'q' to quit or 'ctrl+c' to exit"
	fullMsg := errorMsg + "\n\n" + help

	return ErrorBox(fullMsg, "Scan Error")
}

// renderDatabaseUpdateView renders the enhanced database update progress view
func (m MainModel) renderDatabaseUpdateView() string {
	var content strings.Builder

	header := HeaderStyle.Render("🗄️  Database Update")
	content.WriteString(header)
	content.WriteString("\n")

	if m.currentMessage != "" {
		status := InfoStyle.Render(m.currentMessage)
		content.WriteString(status)
		content.WriteString("\n")
	}

	progressInfo := fmt.Sprintf("Progress: %s", m.progress.View())
	content.WriteString(progressInfo)

	return Box(content.String(), "Updating Vulnerability Database")
}

// renderBOMGenerationView renders the enhanced BOM generation progress view
func (m MainModel) renderBOMGenerationView() string {
	var content strings.Builder

	header := HeaderStyle.Render("📋 BOM Generation")
	content.WriteString(header)
	content.WriteString("\n")

	if m.currentMessage != "" {
		status := InfoStyle.Render(m.currentMessage)
		content.WriteString(status)
		content.WriteString("\n")
	}

	progressInfo := fmt.Sprintf("Progress: %s", m.progress.View())
	content.WriteString(progressInfo)

	return Box(content.String(), "Generating Software Bill of Materials")
}

// renderDetailedResultsView renders detailed vulnerability information
func (m MainModel) renderDetailedResultsView() string {
	if m.bom == nil || m.bom.Vulnerabilities == nil {
		return InfoBox("No vulnerability details available", "Detailed View")
	}

	var content strings.Builder

	// Header
	header := HeaderStyle.Render("📊 Detailed Vulnerability Analysis")
	content.WriteString(header)
	content.WriteString("\n\n")

	// Detailed statistics
	content.WriteString(m.renderDetailedStats())
	content.WriteString("\n")

	// Table with expanded information
	content.WriteString(TitleStyle.Render("🔍 Vulnerability Details"))
	content.WriteString("\n")
	content.WriteString(m.table.View())
	content.WriteString("\n")

	// Additional information
	if m.vulnCount > 0 {
		selectedVuln := m.getSelectedVulnerability()
		if selectedVuln != nil {
			content.WriteString(m.renderVulnerabilityDetail(*selectedVuln))
		}
	}

	// Controls
	controls := []string{
		"↑/↓ navigate",
		"r return",
		"h help",
		"1-5 filter",
		"q quit",
	}
	helpText := strings.Join(controls, " • ")
	content.WriteString(HelpStyle.Render(helpText))

	return content.String()
}

// renderHelpView renders the help screen
func (m MainModel) renderHelpView() string {
	var content strings.Builder

	// Header
	header := HeaderStyle.Render("❓ Help & Controls")
	content.WriteString(header)
	content.WriteString("\n\n")

	// Navigation controls
	navHelp := []string{
		"↑/↓ or k/j - Navigate through vulnerabilities",
		"Enter/Space - Select vulnerability for more details",
		"d - Switch to detailed view",
		"r - Return to summary view",
	}
	content.WriteString(InfoBox(strings.Join(navHelp, "\n"), "Navigation"))
	content.WriteString("\n")

	// Filtering controls
	filterHelp := []string{
		"1 - Show all vulnerabilities",
		"2 - Filter by CRITICAL severity",
		"3 - Filter by HIGH severity",
		"4 - Filter by MEDIUM severity",
		"5 - Filter by LOW severity",
	}
	content.WriteString(InfoBox(strings.Join(filterHelp, "\n"), "Filtering"))
	content.WriteString("\n")

	// General controls
	generalHelp := []string{
		"h or ? - Show this help screen",
		"q or ctrl+c - Quit the application",
		"esc - Return to previous view",
	}
	content.WriteString(InfoBox(strings.Join(generalHelp, "\n"), "General"))
	content.WriteString("\n")

	// Footer
	footer := HelpStyle.Render("Press 'esc' to return to the previous view")
	content.WriteString(footer)

	return content.String()
}

// renderDetailedStats renders detailed vulnerability statistics
func (m MainModel) renderDetailedStats() string {
	var parts []string

	// Risk distribution
	total := m.stats.CriticalVulns + m.stats.HighVulns + m.stats.MediumVulns + m.stats.LowVulns + m.stats.NegligibleVulns
	if total > 0 {
		criticalPct := float64(m.stats.CriticalVulns) / float64(total) * 100
		highPct := float64(m.stats.HighVulns) / float64(total) * 100
		mediumPct := float64(m.stats.MediumVulns) / float64(total) * 100

		riskInfo := fmt.Sprintf("Risk Distribution: %.1f%% Critical, %.1f%% High, %.1f%% Medium",
			criticalPct, highPct, mediumPct)
		parts = append(parts, riskInfo)
	}

	// Component information
	if m.stats.TotalComponents > 0 {
		compInfo := fmt.Sprintf("Components: %d total, %d with vulnerabilities",
			m.stats.TotalComponents, m.countVulnerableComponents())
		parts = append(parts, compInfo)
	}

	// Scanning performance
	if m.stats.ComponentsPerSec > 0 {
		perfInfo := fmt.Sprintf("Performance: %.1f components/sec", m.stats.ComponentsPerSec)
		parts = append(parts, perfInfo)
	}

	if len(parts) == 0 {
		return ""
	}

	return InfoBox(strings.Join(parts, "\n"), "Scan Statistics")
}

// renderVulnerabilityDetail renders detailed information for a specific vulnerability
func (m MainModel) renderVulnerabilityDetail(vuln cyclonedx.Vulnerability) string {
	var content strings.Builder

	content.WriteString(TitleStyle.Render(fmt.Sprintf("🔍 Vulnerability: %s", vuln.ID)))
	content.WriteString("\n")

	// Description
	if vuln.Description != "" {
		content.WriteString(InfoStyle.Render("Description:"))
		content.WriteString("\n")
		content.WriteString(vuln.Description)
		content.WriteString("\n\n")
	}

	// Ratings
	if vuln.Ratings != nil && len(*vuln.Ratings) > 0 {
		content.WriteString(InfoStyle.Render("Severity Ratings:"))
		content.WriteString("\n")
		for _, rating := range *vuln.Ratings {
			severity := GetSeverityStyle(string(rating.Severity)).Render(string(rating.Severity))
			if rating.Score != nil {
				content.WriteString(fmt.Sprintf("• %s (Score: %.1f)", severity, *rating.Score))
			} else {
				content.WriteString(fmt.Sprintf("• %s", severity))
			}
			content.WriteString("\n")
		}
		content.WriteString("\n")
	}

	// References
	if vuln.Advisories != nil && len(*vuln.Advisories) > 0 {
		content.WriteString(InfoStyle.Render("References:"))
		content.WriteString("\n")
		for i, advisory := range *vuln.Advisories {
			if i < 3 { // Limit to first 3 references
				content.WriteString(fmt.Sprintf("• %s", advisory.URL))
				content.WriteString("\n")
			}
		}
		content.WriteString("\n")
	}

	return content.String()
}

// getSelectedVulnerability returns the currently selected vulnerability
func (m MainModel) getSelectedVulnerability() *cyclonedx.Vulnerability {
	if m.bom == nil || m.bom.Vulnerabilities == nil {
		return nil
	}

	vulnerabilities := *m.bom.Vulnerabilities
	if m.selectedIndex >= 0 && m.selectedIndex < len(vulnerabilities) {
		return &vulnerabilities[m.selectedIndex]
	}

	return nil
}

// countVulnerableComponents counts components that have vulnerabilities
func (m MainModel) countVulnerableComponents() int {
	if m.bom == nil || m.bom.Vulnerabilities == nil {
		return 0
	}

	vulnComponents := make(map[string]bool)
	for _, vuln := range *m.bom.Vulnerabilities {
		if vuln.Affects != nil && len(*vuln.Affects) > 0 {
			vulnComponents[(*vuln.Affects)[0].Ref] = true
		}
	}

	return len(vulnComponents)
}

// populateTable populates the table with vulnerability data
func (m *MainModel) populateTable() {
	if m.bom == nil || m.bom.Vulnerabilities == nil || m.bom.Components == nil {
		return
	}

	vulnerabilities := *m.bom.Vulnerabilities
	components := *m.bom.Components

	// Create component lookup map
	componentsMap := make(map[string]cyclonedx.Component)
	for _, c := range components {
		componentsMap[c.BOMRef] = c
	}

	var rows []table.Row
	for _, vuln := range vulnerabilities {
		// Apply severity filter if set
		if m.filterSeverity != "" {
			severity := m.extractSeverity(vuln)
			if severity != m.filterSeverity {
				continue
			}
		}

		row := m.createTableRowFromVuln(vuln, componentsMap)
		if row != nil {
			rows = append(rows, row)
		}
	}

	m.table.SetRows(rows)
}

// createTableRowFromVuln creates a table row from a vulnerability
func (m *MainModel) createTableRowFromVuln(vuln cyclonedx.Vulnerability, componentsMap map[string]cyclonedx.Component) table.Row {
	componentRef := m.getComponentRef(vuln)
	component, exists := componentsMap[componentRef]
	if !exists {
		return nil
	}

	severity := m.extractSeverity(vuln)
	description := m.extractDescription(vuln)

	return table.Row{
		m.truncateString(component.Name, 25),        // Component column
		m.truncateString(component.Version, 15),     // Version column
		m.truncateString(vuln.ID, 18),               // CVE column
		GetSeverityStyle(severity).Render(severity), // Severity column
		m.truncateString(description, 40),           // Description column
	}
}

// getComponentRef extracts component reference from vulnerability
func (m *MainModel) getComponentRef(vuln cyclonedx.Vulnerability) string {
	if vuln.Affects != nil && len(*vuln.Affects) > 0 {
		return (*vuln.Affects)[0].Ref
	}
	return vuln.BOMRef
}

// extractSeverity extracts severity from vulnerability
func (m *MainModel) extractSeverity(vuln cyclonedx.Vulnerability) string {
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

// extractDescription extracts description from vulnerability
func (m *MainModel) extractDescription(vuln cyclonedx.Vulnerability) string {
	if vuln.Description != "" {
		return vuln.Description
	}
	if vuln.Detail != "" {
		return vuln.Detail
	}
	return "No description available"
}

// truncateString truncates a string to the specified length
func (m *MainModel) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// calculateStats calculates vulnerability statistics from the BOM
func (m *MainModel) calculateStats() {
	if m.bom == nil || m.bom.Vulnerabilities == nil {
		return
	}

	m.stats.TotalComponents = 0
	if m.bom.Components != nil {
		m.stats.TotalComponents = len(*m.bom.Components)
	}

	// Reset counters
	m.stats.CriticalVulns = 0
	m.stats.HighVulns = 0
	m.stats.MediumVulns = 0
	m.stats.LowVulns = 0
	m.stats.NegligibleVulns = 0

	for _, vuln := range *m.bom.Vulnerabilities {
		if vuln.Ratings != nil && len(*vuln.Ratings) > 0 {
			severity := string((*vuln.Ratings)[0].Severity)
			switch severity {
			case "CRITICAL":
				m.stats.CriticalVulns++
			case "HIGH":
				m.stats.HighVulns++
			case "MEDIUM":
				m.stats.MediumVulns++
			case "LOW":
				m.stats.LowVulns++
			case "NEGLIGIBLE":
				m.stats.NegligibleVulns++
			}
		}
	}
}
