package spinner

import (
	"fmt"
	"os"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var p *tea.Program

type errMsg error

type model struct {
	spinner spinner.Model
	done    bool
	status  string
	err     error
}

func new(status string) model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#06bd89"))
	return model{
		spinner: s,
		status:  status,
	}
}

func (m model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case bool:
		m.done = true
		return m, tea.Quit

	case errMsg:
		m.err = msg
		return m, nil

	case string:
		m.status = msg
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	default:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
}

func (m model) View() string {
	if m.err != nil {
		return m.err.Error()
	}

	if m.done {
		return ""
	}

	str := fmt.Sprintf("\n %s %s\n\n", m.spinner.View(), m.status)

	return str
}

func Set(status string) {
	p = tea.NewProgram(new(status))
	go func() {
		if _, err := p.Run(); err != nil {
			log.Fatalf("Error running spinner: %v", err)
			os.Exit(1)
		}
	}()
}

func Done() {
	p.Send(true)
}

func Status(val string) {
	p.Send(val)
}
