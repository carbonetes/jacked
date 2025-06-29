package ui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// SpinnerModel represents a simple spinner with message
type SpinnerModel struct {
	spinner spinner.Model
	message string
	width   int
	height  int
}

// NewSpinnerModel creates a new spinner model - compact
func NewSpinnerModel(message string) SpinnerModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return SpinnerModel{
		spinner: s,
		message: message,
		width:   60, // Compact width
		height:  3,  // Compact height
	}
}

// Init initializes the spinner
func (m SpinnerModel) Init() tea.Cmd {
	return m.spinner.Tick
}

// Update handles spinner updates - compact sizing
func (m SpinnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Keep compact - don't resize to full window
		m.width = min(msg.Width, 60)
		m.height = min(msg.Height, 3)
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.spinner, cmd = m.spinner.Update(msg)
	return m, cmd
}

// View renders the spinner - compact inline
func (m SpinnerModel) View() string {
	return fmt.Sprintf("%s %s\n", m.spinner.View(), m.message)
}

// UpdateMessage updates the spinner message
func (m *SpinnerModel) UpdateMessage(message string) {
	m.message = message
}

// ShowSpinner displays a spinner with the given message for the specified duration
func ShowSpinner(message string, duration time.Duration) error {
	m := NewSpinnerModel(message)
	p := tea.NewProgram(m)

	// Auto-quit after duration
	go func() {
		time.Sleep(duration)
		p.Quit()
	}()

	_, err := p.Run()
	return err
}
