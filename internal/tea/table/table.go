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
	baseStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("245"))
)

type model struct {
	table    table.Model
	duration float64
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return m, tea.Quit
		}
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m model) View() string {
	if len(m.table.Rows()) == 0 {
		return baseStyle.Render("No vulnerability had been found!") + fmt.Sprintf("\nDuration: %.3f sec", m.duration) + "\n" + helpStyle.Render("Press esc to quit... 🐱🐓")
	}
	return baseStyle.Render(m.table.View()) + fmt.Sprintf("\nDuration: %.3f sec", m.duration) + "\n" + helpStyle.Render("Press esc to quit... 🐱🐓")
}

func Create(bom *cyclonedx.BOM) table.Model {
	columns := []table.Column{
		{Title: "Component", Width: 28},
		{Title: "Version", Width: 16},
		{Title: "CVE", Width: 16},
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
			log.Error("Component not found for vulnerability: " + v.BOMRef)
			continue
		}
		parts := strings.Split(component, ":")
		name, version := parts[0], parts[1]

		rows = append(rows, table.Row{
			name,
			version,
			v.ID,
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
	m := model{table: t, duration: duration}
	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
