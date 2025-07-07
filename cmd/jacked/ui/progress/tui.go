package progress

import (
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	statusStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffffff")).Render
	emphasisStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#0fa3a6")).Render
)

const (
	padding  = 1
	maxWidth = 75
)

type progressMsg float64

type progressErrMsg struct{ err error }

func finalPause() tea.Cmd {
	return tea.Tick(time.Millisecond*750, func(_ time.Time) tea.Msg {
		return nil
	})
}

type model struct {
	pw       *progressWriter
	progress progress.Model
	err      error
	status   string
	done     bool
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case bool:
		m.done = msg
		return m, nil
	case tea.WindowSizeMsg:
		m.progress.Width = msg.Width - padding*2 - 4
		if m.progress.Width > maxWidth {
			m.progress.Width = maxWidth
		}
		return m, nil

	case progressErrMsg:
		m.err = msg.err
		return m, tea.Quit

	case progressMsg:
		var cmds []tea.Cmd

		if msg >= 1.0 {
			cmds = append(cmds, tea.Sequence(finalPause(), tea.Quit))
		}

		cmds = append(cmds, m.progress.SetPercent(float64(msg)))
		return m, tea.Batch(cmds...)

	// FrameMsg is sent when the progress bar wants to animate itself
	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		m.progress = progressModel.(progress.Model)
		return m, cmd

	default:
		return m, nil
	}
}

func (m model) View() string {
	if m.err != nil {
		return "Error downloading: " + m.err.Error() + "\n"
	}

	if m.done {
		return "\r"
	}

	props := strings.Split(m.status, " ")

	pad := strings.Repeat(" ", padding)
	return "\n" +
		pad + statusStyle(props[0]) + " " + emphasisStyle(props[1]) + "\n" +
		pad + m.progress.View()
}
