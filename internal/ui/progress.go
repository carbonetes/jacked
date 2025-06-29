package ui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
)

// ProgressModel represents a progress view with detailed status
type ProgressModel struct {
	progress       progress.Model
	currentStep    string
	totalSteps     int
	currentStepNum int
	details        []string
	elapsed        time.Duration
	width          int
	height         int
	startTime      time.Time
}

// NewProgressModel creates a new progress model
func NewProgressModel(totalSteps int) ProgressModel {
	prog := progress.New(progress.WithDefaultGradient())
	prog.Width = 30 // Much thinner progress bar

	return ProgressModel{
		progress:       prog,
		totalSteps:     totalSteps,
		currentStepNum: 0,
		details:        make([]string, 0),
		startTime:      time.Now(),
		width:          60, // Smaller width
		height:         3,  // Much smaller height
	}
}

// ProgressUpdateMsg represents a progress update
type ProgressUpdateMsg struct {
	Step       string
	StepNum    int
	Detail     string
	Percentage float64
	Completed  bool
}

// Init initializes the progress model
func (m ProgressModel) Init() tea.Cmd {
	return nil
}

// Update handles progress updates
func (m ProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progress.Width = msg.Width - 20
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}

	case ProgressUpdateMsg:
		m.currentStep = msg.Step
		m.currentStepNum = msg.StepNum
		m.elapsed = time.Since(m.startTime)

		if msg.Detail != "" {
			// Keep only last 5 details
			m.details = append(m.details, msg.Detail)
			if len(m.details) > 5 {
				m.details = m.details[1:]
			}
		}

		if msg.Completed {
			return m, tea.Quit
		}

		return m, m.progress.SetPercent(msg.Percentage)

	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		m.progress = progressModel.(progress.Model)
		return m, cmd
	}

	return m, nil
}

// View renders the progress view - compact inline
func (m ProgressModel) View() string {
	if m.currentStep != "" {
		return fmt.Sprintf("%s %s", m.currentStep, m.progress.View())
	}
	return fmt.Sprintf("Processing %s", m.progress.View())
}

// ShowProgress displays a progress view that can be updated - compact mode
func ShowProgress(totalSteps int) (*tea.Program, ProgressModel) {
	m := NewProgressModel(totalSteps)
	p := tea.NewProgram(m) // No alt screen for compact mode
	return p, m
}

// UpdateProgress sends a progress update to the program
func UpdateProgress(p *tea.Program, step string, stepNum int, detail string, percentage float64) {
	if p != nil {
		p.Send(ProgressUpdateMsg{
			Step:       step,
			StepNum:    stepNum,
			Detail:     detail,
			Percentage: percentage,
			Completed:  false,
		})
	}
}

// CompleteProgress marks the progress as complete
func CompleteProgress(p *tea.Program) {
	if p != nil {
		p.Send(ProgressUpdateMsg{
			Step:      "Complete",
			Completed: true,
		})
	}
}
