package table

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	helpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Margin(1, 0)
	baseStyle = lipgloss.NewStyle().BorderStyle(lipgloss.HiddenBorder())
)

type model struct {
	table    table.Model
	duration float64
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc", "enter", " ":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m model) View() string {
	if len(m.table.Rows()) == 0 {
		return baseStyle.Render("No vulnerabilities found") +
			fmt.Sprintf("\nScan duration: %.3f seconds", m.duration) +
			"\n\nPress any key to continue..."
	}

	footer := fmt.Sprintf("Vulnerability Report (%v found) \nScan duration: %.3f seconds\n\nPress 'q' or any key to exit", len(m.table.Rows()), m.duration)
	return lipgloss.JoinVertical(lipgloss.Left,
		baseStyle.Render(m.table.View()),
		helpStyle.Render(footer),
	)
}

func Create(bom *cyclonedx.BOM) table.Model {
	if bom == nil || bom.Vulnerabilities == nil || bom.Components == nil {
		log.Debug("No vulnerabilities found in BOM")
		// Return empty table with no columns when there's no data
		return table.New()
	}

	columns := []table.Column{
		{Title: "Component", Width: 28},
		{Title: "Version", Width: 18},
		{Title: "CVE ID", Width: 18},
		{Title: "Severity", Width: 20},
		{Title: "Fix Available", Width: 40},
	}

	var rows []table.Row
	vulnerabilities := bom.Vulnerabilities
	components := bom.Components

	// Create component lookup map
	componentsMap := createComponentMap(components)

	// Sort vulnerabilities by severity (critical first) then by BOM ref
	sortVulnerabilitiesBySeverity(vulnerabilities)

	// Process each vulnerability
	for _, v := range *vulnerabilities {
		row := createVulnerabilityRow(v, componentsMap)
		if row != nil {
			rows = append(rows, *row)
		}
	}

	return createStyledTable(columns, rows)
}

// createComponentMap creates a lookup map for components
func createComponentMap(components *[]cyclonedx.Component) map[string]string {
	componentsMap := make(map[string]string)
	for _, c := range *components {
		componentsMap[c.BOMRef] = c.Name + ":" + c.Version
	}
	return componentsMap
}

// sortVulnerabilitiesBySeverity sorts vulnerabilities by severity (critical first) then by BOM ref
func sortVulnerabilitiesBySeverity(vulnerabilities *[]cyclonedx.Vulnerability) {
	severityOrder := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
		"UNKNOWN":  0,
	}

	sort.Slice(*vulnerabilities, func(i, j int) bool {
		sev1 := getSeverityFromVuln((*vulnerabilities)[i])
		sev2 := getSeverityFromVuln((*vulnerabilities)[j])

		order1, exists1 := severityOrder[sev1]
		order2, exists2 := severityOrder[sev2]

		if !exists1 {
			order1 = 0
		}
		if !exists2 {
			order2 = 0
		}

		if order1 != order2 {
			return order1 > order2 // Higher severity first
		}

		return (*vulnerabilities)[i].BOMRef < (*vulnerabilities)[j].BOMRef
	})
}

// createVulnerabilityRow creates a table row for a vulnerability
func createVulnerabilityRow(v cyclonedx.Vulnerability, componentsMap map[string]string) *table.Row {
	component, ok := componentsMap[v.BOMRef]
	if !ok {
		log.Debug("Component not found for vulnerability: " + v.BOMRef)
		return nil
	}

	name, version := parseComponentNameVersion(component)
	severity := getSeverityFromVuln(v)
	recommendation := getRecommendation(v)

	row := table.Row{
		name,
		version,
		v.ID,
		severity,
		recommendation,
	}
	return &row
}

// parseComponentNameVersion splits component string into name and version
func parseComponentNameVersion(component string) (string, string) {
	parts := strings.Split(component, ":")
	name := parts[0]

	var version string
	if len(parts) > 2 {
		version = strings.Join(parts[1:], ":")
	} else if len(parts) == 2 {
		version = parts[1]
	}

	return name, version
}

// getSeverityFromVuln extracts severity from vulnerability ratings
func getSeverityFromVuln(v cyclonedx.Vulnerability) string {
	if v.Ratings != nil && len(*v.Ratings) > 0 {
		for _, r := range *v.Ratings {
			if r.Severity != "" {
				return strings.ToUpper(string(r.Severity))
			}
		}
	}
	return "UNKNOWN"
}

// getRecommendation gets recommendation text, with fallback for empty values
func getRecommendation(v cyclonedx.Vulnerability) string {
	if v.Recommendation != "" {
		return v.Recommendation
	}
	return "Update to latest version"
}

// createStyledTable creates and styles the table
func createStyledTable(columns []table.Column, rows []table.Row) table.Model {
	// Calculate height to show all rows plus header
	tableHeight := len(rows) + 3 // +2 for header and border
	if tableHeight < 5 {
		tableHeight = 5 // Minimum height
	}
	if tableHeight > 30 {
		tableHeight = 30 // Maximum height to prevent excessive screen usage
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(false), // Remove focus to disable interactivity
		table.WithHeight(tableHeight),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true).
		Foreground(lipgloss.Color("255"))
	// Remove selected row styling since table is not interactive
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("")).
		Background(lipgloss.Color("")).
		Bold(false)
	t.SetStyles(s)

	return t
}

func Show(t table.Model, duration float64) {
	m := model{table: t, duration: duration}

	// Create program without alt screen to prevent clearing
	p := tea.NewProgram(m)

	defer func() {
		if r := recover(); r != nil {
			// Ensure terminal is restored on panic
			fmt.Fprintf(os.Stderr, "UI error: %v\n", r)
		}
	}()

	if _, err := p.Run(); err != nil {
		// Don't exit on error, just log it and continue
		fmt.Fprintf(os.Stderr, "Error displaying table: %v\n", err)
	}
}
