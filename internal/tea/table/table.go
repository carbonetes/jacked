package table

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	helpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Margin(1, 0)
	baseStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("245"))
	NonInteractive = false // Add flag to control interactive mode
)

type model struct {
	table          table.Model
	duration       float64
	nonInteractive bool
}

type autoExitMsg struct{}

func (m model) Init() tea.Cmd {
	if m.nonInteractive {
		// Auto-exit after a short delay in non-interactive mode
		return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
			return autoExitMsg{}
		})
	}
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "q", "ctrl+c":
			return m, tea.Quit
		}
	case autoExitMsg:
		// Auto-exit in non-interactive mode
		return m, tea.Quit
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m model) View() string {
	helpText := "Press esc to quit... 🐱🐓"
	if m.nonInteractive {
		helpText = "Exiting..."
	}

	if len(m.table.Rows()) == 0 {
		return baseStyle.Render("No vulnerability had been found!") + fmt.Sprintf("\nDuration: %.3f sec", m.duration) + "\n" + helpStyle.Render(helpText)
	}
	return baseStyle.Render(m.table.View()) + fmt.Sprintf("\nDuration: %.3f sec", m.duration) + "\n" + helpStyle.Render(helpText)
}

func Create(bom *cyclonedx.BOM) table.Model {

	if bom == nil || bom.Vulnerabilities == nil || bom.Components == nil {
		log.Debug("No vulnerabilities found in BOM")
		return table.New()
	}

	columns := []table.Column{
		{Title: "Component", Width: 24},
		{Title: "Version", Width: 16},
		{Title: "CVE", Width: 16},
		{Title: "Severity", Width: 16},
		{Title: "Recommendation", Width: 42},
	}

	var rows []table.Row
	vulnerabilities := bom.Vulnerabilities
	components := bom.Components

	// Put component names and versions in a map for easy lookup
	componentsMap := make(map[string]string)
	for _, c := range *components {
		componentsMap[c.BOMRef] = c.Name + ":" + c.Version
	}

	// Sort vulnerabilities by bom ref
	sort.Slice(*vulnerabilities, func(i, j int) bool {
		return (*vulnerabilities)[i].BOMRef < (*vulnerabilities)[j].BOMRef
	})

	for _, v := range *vulnerabilities {
		component, ok := componentsMap[v.BOMRef]
		if !ok {
			log.Debug("Component not found for vulnerability: " + v.BOMRef)
			continue
		}
		// Split the component into name and version
		// Assuming the format is "name:version" or "name:epoch:upstream_version:build"
		parts := strings.Split(component, ":")
		name := parts[0]
		// the rest of the parts are the version
		version := ""
		if len(parts) > 2 {
			version = strings.Join(parts[1:], ":")
		} else if len(parts) == 2 {
			version = parts[1]
		}

		severity := "UNKNOWN"
		if v.Ratings != nil && len(*v.Ratings) > 0 {
			for _, r := range *v.Ratings {
				if r.Severity != "" {
					severity = string(r.Severity)
					break
				}
			}
		}

		rows = append(rows, table.Row{
			name,
			version,
			v.ID,
			severity,
			v.Recommendation,
		})
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	return t
}

func Show(t table.Model, duration float64) {
	m := model{table: t, duration: duration, nonInteractive: NonInteractive}
	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(0)
	}
}

func ShowNonInteractive(t table.Model, duration float64) {
	m := model{table: t, duration: duration, nonInteractive: true}
	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(0)
	}
}
