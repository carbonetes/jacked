package ui

import (
	"fmt"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// TableViewModel represents a Bubble Tea table view model
type TableViewModel struct {
	table       table.Model
	bom         *cyclonedx.BOM
	width       int
	height      int
	showSummary bool
}

// NewTableViewModel creates a new table view model - compact
func NewTableViewModel(bom *cyclonedx.BOM) TableViewModel {
	columns := calculateResponsiveColumns(getTerminalWidth())

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(false), // Not interactive
		table.WithHeight(8),      // Compact height
	)

	// Apply custom styles - no selection style for non-interactive, no borders
	s := table.DefaultStyles()
	s.Header = TableHeaderStyle
	// Remove selection styling since it's not interactive
	s.Selected = s.Cell // Use normal cell style instead of selection style
	// Remove all borders for clean output
	s.Cell = s.Cell.BorderStyle(lipgloss.NormalBorder()).BorderTop(false).BorderBottom(false).BorderLeft(false).BorderRight(false)
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderTop(false).BorderBottom(false).BorderLeft(false).BorderRight(false)
	t.SetStyles(s)

	vm := TableViewModel{
		table:       t,
		bom:         bom,
		width:       90,    // Compact width
		height:      12,    // Compact height
		showSummary: false, // No summary for compact view
	}

	vm.populateTable()
	return vm
}

// Init initializes the table view model
func (m TableViewModel) Init() tea.Cmd {
	return nil
}

// Update handles messages for the table view
func (m TableViewModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.table.SetHeight(msg.Height - 10) // Leave space for header and footer

		// Recalculate columns for new terminal width
		newColumns := calculateResponsiveColumns(msg.Width)
		m.table.SetColumns(newColumns)

		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "s":
			m.showSummary = !m.showSummary
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

// View renders the table view
func (m TableViewModel) View() string {
	var b strings.Builder

	vulnCount := 0
	if m.bom != nil && m.bom.Vulnerabilities != nil {
		vulnCount = len(*m.bom.Vulnerabilities)
	}

	// Header with title and counts
	title := TitleStyle.Render(fmt.Sprintf("Vulnerability Scan Results (%d vulnerabilities)", vulnCount))
	b.WriteString(title)
	b.WriteString("\n")

	if m.showSummary && vulnCount > 0 {
		// Summary line
		summary := m.generateSummaryLine()
		b.WriteString(InfoStyle.Render(summary))
		b.WriteString("\n")
	}

	b.WriteString("\n")

	if vulnCount == 0 {
		// No vulnerabilities found
		noVulns := SuccessStyle.
			Align(lipgloss.Center).
			Width(m.width - 4).
			Render("No security vulnerabilities found!")
		b.WriteString(Box(noVulns, ""))
	} else {
		// Table with vulnerabilities
		b.WriteString(m.table.View())
	}

	b.WriteString("\n")

	return ContainerStyle.
		Width(m.width).
		Height(m.height).
		Render(b.String())
}

// populateTable populates the table with vulnerability data
func (m *TableViewModel) populateTable() {
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
		row := m.createTableRowFromVuln(vuln, componentsMap)
		if row != nil {
			rows = append(rows, row)
		}
	}

	m.table.SetRows(rows)
}

// createTableRowFromVuln creates a table row from a vulnerability
func (m *TableViewModel) createTableRowFromVuln(vuln cyclonedx.Vulnerability, componentsMap map[string]cyclonedx.Component) table.Row {
	componentRef := m.getComponentRef(vuln)
	component, exists := componentsMap[componentRef]
	if !exists {
		return nil
	}

	severity := m.extractSeverity(vuln)
	description := m.extractDescription(vuln)

	return table.Row{
		m.truncateString(component.Name, 28),
		m.truncateString(component.Version, 18),
		m.truncateString(vuln.ID, 16),
		severity, // Keep unstyled for table compatibility
		m.truncateString(description, 40),
	}
}

// Helper methods (copied from MainModel for consistency)
func (m *TableViewModel) getComponentRef(vuln cyclonedx.Vulnerability) string {
	if vuln.Affects != nil && len(*vuln.Affects) > 0 {
		return (*vuln.Affects)[0].Ref
	}
	return vuln.BOMRef
}

func (m *TableViewModel) extractSeverity(vuln cyclonedx.Vulnerability) string {
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

func (m *TableViewModel) extractDescription(vuln cyclonedx.Vulnerability) string {
	if vuln.Description != "" {
		return vuln.Description
	}
	if vuln.Detail != "" {
		return vuln.Detail
	}
	return "No description available"
}

func (m *TableViewModel) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// generateSummaryLine creates a summary line showing vulnerability counts by severity
func (m *TableViewModel) generateSummaryLine() string {
	if m.bom == nil || m.bom.Vulnerabilities == nil {
		return ""
	}

	vulnerabilities := *m.bom.Vulnerabilities
	counts := map[string]int{
		"CRITICAL":   0,
		"HIGH":       0,
		"MEDIUM":     0,
		"LOW":        0,
		"NEGLIGIBLE": 0,
		"UNKNOWN":    0,
	}

	for _, vuln := range vulnerabilities {
		severity := m.extractSeverity(vuln)
		counts[severity]++
	}

	var parts []string
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"} {
		if counts[severity] > 0 {
			styled := GetSeverityStyle(severity).Render(fmt.Sprintf("%s: %d", severity, counts[severity]))
			parts = append(parts, styled)
		}
	}

	if len(parts) == 0 {
		return "No vulnerabilities by severity"
	}

	return strings.Join(parts, " • ")
}

// calculateResponsiveColumns calculates column widths based on terminal size
func calculateResponsiveColumns(terminalWidth int) []table.Column {
	// Reserve space for borders and padding (approximately 10 characters)
	availableWidth := terminalWidth - 10

	// Minimum widths for readability
	minComponentWidth := 15
	minVersionWidth := 8
	minCVEWidth := 12
	minSeverityWidth := 8
	minDescWidth := 20

	// Calculate minimum total width needed
	minTotalWidth := minComponentWidth + minVersionWidth + minCVEWidth + minSeverityWidth + minDescWidth

	if availableWidth < minTotalWidth {
		// Very small terminal - use minimal columns
		if availableWidth < 50 {
			return []table.Column{
				{Title: "Component", Width: 20},
				{Title: "CVE", Width: 15},
				{Title: "Severity", Width: 8},
			}
		}
		// Small terminal - reduced widths
		return []table.Column{
			{Title: "Component", Width: minComponentWidth},
			{Title: "Version", Width: minVersionWidth},
			{Title: "CVE", Width: minCVEWidth},
			{Title: "Severity", Width: minSeverityWidth},
			{Title: "Description", Width: minDescWidth},
		}
	}

	// Normal terminal - distribute extra space proportionally
	extraWidth := availableWidth - minTotalWidth

	// Distribute extra width: more to component and description
	componentWidth := minComponentWidth + (extraWidth * 30 / 100) // 30% of extra
	descWidth := minDescWidth + (extraWidth * 50 / 100)           // 50% of extra
	versionWidth := minVersionWidth + (extraWidth * 10 / 100)     // 10% of extra
	cveWidth := minCVEWidth + (extraWidth * 10 / 100)             // 10% of extra

	return []table.Column{
		{Title: "Component", Width: componentWidth},
		{Title: "Version", Width: versionWidth},
		{Title: "CVE", Width: cveWidth},
		{Title: "Severity", Width: minSeverityWidth}, // Keep severity width fixed
		{Title: "Description", Width: descWidth},
	}
}

// ShowTableResults displays results using the Bubble Tea table
func ShowTableResults(bom *cyclonedx.BOM) error {
	m := NewTableViewModel(bom)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
