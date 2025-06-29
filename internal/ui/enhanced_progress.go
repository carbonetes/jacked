package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// EnhancedProgress represents an enhanced progress indicator
type EnhancedProgress struct {
	spinner     spinner.Model
	title       string
	message     string
	percentage  float64
	showSpinner bool
	showStats   bool
	stats       ProgressStats
	style       EnhancedProgressStyle
}

// ProgressStats holds progress statistics
type ProgressStats struct {
	StartTime     time.Time
	ItemsTotal    int
	ItemsComplete int
	ItemsPerSec   float64
	ETA           time.Duration
}

// EnhancedProgressStyle defines the visual style of the progress indicator
type EnhancedProgressStyle struct {
	TitleStyle   lipgloss.Style
	MessageStyle lipgloss.Style
	BarStyle     lipgloss.Style
	StatsStyle   lipgloss.Style
}

// NewEnhancedProgress creates a new enhanced progress indicator
func NewEnhancedProgress(title string) EnhancedProgress {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(accentColor)

	return EnhancedProgress{
		spinner:     s,
		title:       title,
		showSpinner: true,
		showStats:   true,
		style: EnhancedProgressStyle{
			TitleStyle:   HeaderStyle,
			MessageStyle: InfoStyle,
			BarStyle:     ProgressBarStyle,
			StatsStyle:   MutedStyle,
		},
		stats: ProgressStats{
			StartTime: time.Now(),
		},
	}
}

// SetMessage sets the current progress message
func (p *EnhancedProgress) SetMessage(message string) {
	p.message = message
}

// SetPercentage sets the progress percentage (0.0 to 1.0)
func (p *EnhancedProgress) SetPercentage(percentage float64) {
	p.percentage = percentage
	p.updateStats()
}

// SetItemProgress sets progress based on item counts
func (p *EnhancedProgress) SetItemProgress(completed, total int) {
	p.stats.ItemsComplete = completed
	p.stats.ItemsTotal = total
	if total > 0 {
		p.percentage = float64(completed) / float64(total)
	}
	p.updateStats()
}

// updateStats calculates progress statistics
func (p *EnhancedProgress) updateStats() {
	elapsed := time.Since(p.stats.StartTime).Seconds()
	if elapsed > 0 && p.stats.ItemsComplete > 0 {
		p.stats.ItemsPerSec = float64(p.stats.ItemsComplete) / elapsed

		if p.stats.ItemsPerSec > 0 && p.stats.ItemsTotal > p.stats.ItemsComplete {
			remaining := p.stats.ItemsTotal - p.stats.ItemsComplete
			p.stats.ETA = time.Duration(float64(remaining)/p.stats.ItemsPerSec) * time.Second
		}
	}
}

// Update updates the progress indicator for Bubble Tea
func (p EnhancedProgress) Update(msg tea.Msg) (EnhancedProgress, tea.Cmd) {
	var cmd tea.Cmd
	if p.showSpinner {
		p.spinner, cmd = p.spinner.Update(msg)
	}
	return p, cmd
}

// View renders the progress indicator
func (p EnhancedProgress) View() string {
	var content strings.Builder

	// Title with optional spinner
	titleLine := p.style.TitleStyle.Render(p.title)
	if p.showSpinner && p.percentage < 1.0 {
		titleLine = fmt.Sprintf("%s %s", titleLine, p.spinner.View())
	}
	content.WriteString(titleLine)
	content.WriteString("\n")

	// Message
	if p.message != "" {
		content.WriteString(p.style.MessageStyle.Render(p.message))
		content.WriteString("\n")
	}

	// Progress bar
	content.WriteString(p.renderProgressBar())
	content.WriteString("\n")

	// Statistics
	if p.showStats {
		content.WriteString(p.renderStats())
	}

	return Box(content.String(), "")
}

// renderProgressBar renders the visual progress bar
func (p EnhancedProgress) renderProgressBar() string {
	barWidth := 40
	filled := int(p.percentage * float64(barWidth))

	var bar strings.Builder
	bar.WriteString("[")

	// Filled portion
	for i := 0; i < filled; i++ {
		bar.WriteString("█")
	}

	// Empty portion
	for i := filled; i < barWidth; i++ {
		bar.WriteString("░")
	}

	bar.WriteString("]")

	// Percentage
	percentage := fmt.Sprintf(" %.1f%%", p.percentage*100)
	bar.WriteString(percentage)

	return p.style.BarStyle.Render(bar.String())
}

// renderStats renders progress statistics
func (p EnhancedProgress) renderStats() string {
	var stats []string

	// Items progress
	if p.stats.ItemsTotal > 0 {
		stats = append(stats, fmt.Sprintf("%d/%d items", p.stats.ItemsComplete, p.stats.ItemsTotal))
	}

	// Speed
	if p.stats.ItemsPerSec > 0 {
		stats = append(stats, fmt.Sprintf("%.1f items/sec", p.stats.ItemsPerSec))
	}

	// ETA
	if p.stats.ETA > 0 {
		stats = append(stats, fmt.Sprintf("ETA: %v", p.stats.ETA.Truncate(time.Second)))
	}

	// Elapsed time
	elapsed := time.Since(p.stats.StartTime)
	stats = append(stats, fmt.Sprintf("Elapsed: %v", elapsed.Truncate(time.Second)))

	if len(stats) == 0 {
		return ""
	}

	return p.style.StatsStyle.Render(strings.Join(stats, " • "))
}

// SetShowSpinner controls whether to show the spinner
func (p *EnhancedProgress) SetShowSpinner(show bool) {
	p.showSpinner = show
}

// SetShowStats controls whether to show statistics
func (p *EnhancedProgress) SetShowStats(show bool) {
	p.showStats = show
}

// IsComplete returns true if progress is complete
func (p EnhancedProgress) IsComplete() bool {
	return p.percentage >= 1.0
}
