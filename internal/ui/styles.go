package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	// Enhanced color palette
	primaryColor    = lipgloss.Color("#FF6B6B") // Modern red
	accentColor     = lipgloss.Color("#4ECDC4") // Teal
	successColor    = lipgloss.Color("#45B7D1") // Blue
	warningColor    = lipgloss.Color("#FFA726") // Orange
	errorColor      = lipgloss.Color("#EF5350") // Red
	infoColor       = lipgloss.Color("#66BB6A") // Green
	mutedColor      = lipgloss.Color("#78909C") // Blue gray
	highlightColor  = lipgloss.Color("#9C27B0") // Purple
	backgroundLight = lipgloss.Color("#F5F5F5") // Light background
	textPrimary     = lipgloss.Color("#212121") // Dark text
	textSecondary   = lipgloss.Color("#757575") // Gray text
	borderColor     = lipgloss.Color("#E0E0E0") // Light border

	// Common colors for reuse
	whiteColor = lipgloss.Color("#FFFFFF")
	blackColor = lipgloss.Color("#000000")

	// Severity colors
	severityCritical = lipgloss.Color("#D32F2F")
	severityHigh     = lipgloss.Color("#F57C00")
	severityMedium   = lipgloss.Color("#FFC107")
	severityLow      = lipgloss.Color("#388E3C")
	severityInfo     = lipgloss.Color("#757575")
	severityDefault  = lipgloss.Color("#9E9E9E")

	// Enhanced title styles with better typography
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(primaryColor).
			MarginBottom(1).
			PaddingLeft(1).
			Border(lipgloss.Border{Left: "▌"}).
			BorderForeground(primaryColor)

	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(accentColor).
			MarginBottom(1).
			PaddingLeft(2).
			Border(lipgloss.Border{Left: "┃"}).
			BorderForeground(accentColor)

	SuccessTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(successColor).
				MarginBottom(1).
				PaddingLeft(1).
				Border(lipgloss.Border{Left: "▌"}).
				BorderForeground(successColor)

	ErrorTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(errorColor).
			MarginBottom(1).
			PaddingLeft(1).
			Border(lipgloss.Border{Left: "▌"}).
			BorderForeground(errorColor)

	// Enhanced text styles
	InfoStyle = lipgloss.NewStyle().
			Foreground(infoColor).
			PaddingLeft(1)

	MutedStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			Italic(true)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(errorColor).
			Bold(true)

	SuccessStyle = lipgloss.NewStyle().
			Foreground(successColor).
			Bold(true)

	HelpStyle = lipgloss.NewStyle().
			Foreground(textSecondary).
			Italic(true).
			MarginTop(1)

	StatStyle = lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true).
			PaddingLeft(1).
			PaddingRight(1).
			Background(backgroundLight).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(borderColor)

	// Enhanced container and layout styles
	ContainerStyle = lipgloss.NewStyle().
			Padding(1, 2).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(borderColor)

	CardStyle = lipgloss.NewStyle().
			Padding(1, 2).
			MarginBottom(1).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(borderColor).
			Background(backgroundLight)

	// Enhanced progress styles
	ProgressStyle = lipgloss.NewStyle().
			MarginTop(1).
			MarginBottom(1).
			PaddingLeft(1).
			PaddingRight(1)

	ProgressBarStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(borderColor).
				Padding(0, 1)

	// Enhanced table styles - borderless for clean output
	TableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(textPrimary).
				Background(backgroundLight).
				Padding(0, 1)

	TableSelectedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("255")).
				Background(highlightColor).
				Bold(true).
				Padding(0, 1)

	TableRowStyle = lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(textPrimary)

	TableEvenRowStyle = lipgloss.NewStyle().
				Padding(0, 1).
				Foreground(textPrimary).
				Background(backgroundLight)
)

// GetSeverityStyle returns an enhanced style based on vulnerability severity
func GetSeverityStyle(severity string) lipgloss.Style {
	switch severity {
	case "CRITICAL":
		return lipgloss.NewStyle().
			Foreground(whiteColor).
			Background(severityCritical).
			Bold(true).
			Padding(0, 1).
			BorderStyle(lipgloss.RoundedBorder())
	case "HIGH":
		return lipgloss.NewStyle().
			Foreground(whiteColor).
			Background(severityHigh).
			Bold(true).
			Padding(0, 1).
			BorderStyle(lipgloss.RoundedBorder())
	case "MEDIUM":
		return lipgloss.NewStyle().
			Foreground(blackColor).
			Background(severityMedium).
			Bold(true).
			Padding(0, 1).
			BorderStyle(lipgloss.RoundedBorder())
	case "LOW":
		return lipgloss.NewStyle().
			Foreground(whiteColor).
			Background(severityLow).
			Bold(true).
			Padding(0, 1).
			BorderStyle(lipgloss.RoundedBorder())
	case "NEGLIGIBLE":
		return lipgloss.NewStyle().
			Foreground(whiteColor).
			Background(severityInfo).
			Padding(0, 1).
			BorderStyle(lipgloss.RoundedBorder())
	default:
		return lipgloss.NewStyle().
			Foreground(whiteColor).
			Background(severityDefault).
			Padding(0, 1).
			BorderStyle(lipgloss.RoundedBorder())
	}
}

// Center centers content within the given width
func Center(content string, width int) string {
	return lipgloss.NewStyle().
		Width(width).
		Align(lipgloss.Center).
		Render(content)
}

// Box creates a bordered box around content with enhanced styling
func Box(content string, title string) string {
	boxStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Padding(1, 2).
		MarginBottom(1)

	if title != "" {
		titleStyle := HeaderStyle.Copy().MarginBottom(0)
		content = titleStyle.Render(title) + "\n" + content
	}

	return boxStyle.Render(content)
}

// InfoBox creates an informational box with an icon
func InfoBox(content string, title string) string {
	icon := "ℹ️ "
	if title != "" {
		title = icon + title
	} else {
		content = icon + content
	}

	boxStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(infoColor).
		Padding(1, 2).
		MarginBottom(1).
		Background(backgroundLight)

	if title != "" {
		titleStyle := InfoStyle.Copy().Bold(true).MarginBottom(0)
		content = titleStyle.Render(title) + "\n" + content
	}

	return boxStyle.Render(content)
}

// WarningBox creates a warning box with an icon
func WarningBox(content string, title string) string {
	icon := "⚠️  "
	if title != "" {
		title = icon + title
	} else {
		content = icon + content
	}

	boxStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(warningColor).
		Padding(1, 2).
		MarginBottom(1).
		Background(backgroundLight)

	if title != "" {
		titleStyle := lipgloss.NewStyle().
			Foreground(warningColor).
			Bold(true).
			MarginBottom(0)
		content = titleStyle.Render(title) + "\n" + content
	}

	return boxStyle.Render(content)
}

// ErrorBox creates an error box with an icon
func ErrorBox(content string, title string) string {
	icon := "❌ "
	if title != "" {
		title = icon + title
	} else {
		content = icon + content
	}

	boxStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(errorColor).
		Padding(1, 2).
		MarginBottom(1).
		Background(backgroundLight)

	if title != "" {
		titleStyle := ErrorTitleStyle.Copy().MarginBottom(0)
		content = titleStyle.Render(title) + "\n" + content
	}

	return boxStyle.Render(content)
}

// SuccessBox creates a success box with an icon
func SuccessBox(content string, title string) string {
	icon := "✅ "
	if title != "" {
		title = icon + title
	} else {
		content = icon + content
	}

	boxStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(successColor).
		Padding(1, 2).
		MarginBottom(1).
		Background(backgroundLight)

	if title != "" {
		titleStyle := SuccessTitleStyle.Copy().MarginBottom(0)
		content = titleStyle.Render(title) + "\n" + content
	}

	return boxStyle.Render(content)
}

// ProgressBox creates a box for displaying progress information
func ProgressBox(content string, percentage float64) string {
	progressBar := lipgloss.NewStyle().
		Foreground(accentColor).
		Render(fmt.Sprintf("%.1f%%", percentage*100))

	fullContent := content + "\n" + progressBar

	boxStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(accentColor).
		Padding(1, 2).
		MarginBottom(1)

	return boxStyle.Render(fullContent)
}

// StatCard creates a styled card for displaying statistics
func StatCard(label string, value string, description string) string {
	labelStyle := lipgloss.NewStyle().
		Foreground(textSecondary).
		Bold(true)

	valueStyle := lipgloss.NewStyle().
		Foreground(accentColor).
		Bold(true).
		MarginBottom(0)

	descStyle := lipgloss.NewStyle().
		Foreground(textSecondary).
		Italic(true)

	content := labelStyle.Render(label) + "\n" +
		valueStyle.Render(value)

	if description != "" {
		content += "\n" + descStyle.Render(description)
	}

	return CardStyle.Render(content)
}

// Divider creates a visual divider
func Divider(width int) string {
	return lipgloss.NewStyle().
		Foreground(borderColor).
		Width(width).
		Render(strings.Repeat("─", width))
}

// Badge creates a small badge/tag
func Badge(text string, color lipgloss.Color) string {
	return lipgloss.NewStyle().
		Foreground(whiteColor).
		Background(color).
		Padding(0, 1).
		BorderStyle(lipgloss.RoundedBorder()).
		Render(text)
}
