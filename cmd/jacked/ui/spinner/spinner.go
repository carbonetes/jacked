package spinner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	p        *tea.Program
	Skip     = true
	mu       sync.Mutex
	done     = make(chan bool, 1)
	finished bool
)

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
	mu.Lock()
	defer mu.Unlock()

	if Skip || finished {
		return
	}

	// Clean up any existing program
	cleanup()

	p = tea.NewProgram(new(status), tea.WithAltScreen())

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Debugf("Spinner panic recovered: %v", r)
			}
		}()

		// Use context with timeout to prevent hanging
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		errChan := make(chan error, 1)
		go func() {
			_, err := p.Run()
			errChan <- err
		}()

		select {
		case err := <-errChan:
			if err != nil {
				log.Debugf("Spinner error: %v", err)
			}
		case <-ctx.Done():
			log.Debug("Spinner timed out")
			if p != nil {
				p.Kill()
			}
		case <-done:
			// Normal completion
		}
	}()
}

func Done() {
	mu.Lock()
	defer mu.Unlock()

	if Skip || finished {
		return
	}

	finished = true

	// Signal completion
	select {
	case done <- true:
	default:
	}

	if p != nil {
		p.Send(true)
		// Give it a moment to clean up
		time.Sleep(100 * time.Millisecond)
	}

	cleanup()
}

func Status(val string) {
	mu.Lock()
	defer mu.Unlock()

	if Skip || finished || p == nil {
		return
	}
	p.Send(val)
}

func cleanup() {
	if p != nil {
		p.Kill()
		p = nil
	}
}
