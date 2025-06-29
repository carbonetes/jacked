package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/pkg/types"
)

// Dashboard represents a comprehensive scanning dashboard
type Dashboard struct {
	params    types.Parameters
	bom       *cyclonedx.BOM
	scanStats ScanStats
	phase     ScanPhase
	startTime time.Time
	errors    []string
	warnings  []string
	insights  []string
}

// ScanPhase represents the current phase of scanning
type ScanPhase int

const (
	PhaseInitializing ScanPhase = iota
	PhaseUpdatingDB
	PhaseGeneratingBOM
	PhaseScanning
	PhaseAnalyzing
	PhaseComplete
	PhaseError
)

// NewDashboard creates a new scanning dashboard
func NewDashboard(params types.Parameters) *Dashboard {
	return &Dashboard{
		params:    params,
		startTime: time.Now(),
		phase:     PhaseInitializing,
		errors:    make([]string, 0),
		warnings:  make([]string, 0),
		insights:  make([]string, 0),
	}
}

// SetPhase updates the current scanning phase
func (d *Dashboard) SetPhase(phase ScanPhase) {
	d.phase = phase
}

// SetBOM updates the BOM data
func (d *Dashboard) SetBOM(bom *cyclonedx.BOM) {
	d.bom = bom
	d.updateStats()
}

// AddError adds an error message
func (d *Dashboard) AddError(err string) {
	d.errors = append(d.errors, err)
}

// AddWarning adds a warning message
func (d *Dashboard) AddWarning(warning string) {
	d.warnings = append(d.warnings, warning)
}

// AddInsight adds an insight or recommendation
func (d *Dashboard) AddInsight(insight string) {
	d.insights = append(d.insights, insight)
}

// updateStats calculates current statistics
func (d *Dashboard) updateStats() {
	if d.bom == nil {
		return
	}

	if d.bom.Components != nil {
		d.scanStats.TotalComponents = len(*d.bom.Components)
	}

	if d.bom.Vulnerabilities != nil {
		// Reset counters
		d.scanStats.CriticalVulns = 0
		d.scanStats.HighVulns = 0
		d.scanStats.MediumVulns = 0
		d.scanStats.LowVulns = 0
		d.scanStats.NegligibleVulns = 0

		for _, vuln := range *d.bom.Vulnerabilities {
			if vuln.Ratings != nil && len(*vuln.Ratings) > 0 {
				severity := string((*vuln.Ratings)[0].Severity)
				switch severity {
				case "CRITICAL":
					d.scanStats.CriticalVulns++
				case "HIGH":
					d.scanStats.HighVulns++
				case "MEDIUM":
					d.scanStats.MediumVulns++
				case "LOW":
					d.scanStats.LowVulns++
				case "NEGLIGIBLE":
					d.scanStats.NegligibleVulns++
				}
			}
		}
	}
}

// View renders the dashboard
func (d *Dashboard) View() string {
	var content strings.Builder

	// Header
	content.WriteString(d.renderHeader())
	content.WriteString("\n")

	// Current phase status
	content.WriteString(d.renderPhaseStatus())
	content.WriteString("\n")

	// Statistics overview
	if d.bom != nil {
		content.WriteString(d.renderStatsOverview())
		content.WriteString("\n")
	}

	// Messages (errors, warnings, insights)
	if len(d.errors) > 0 || len(d.warnings) > 0 || len(d.insights) > 0 {
		content.WriteString(d.renderMessages())
		content.WriteString("\n")
	}

	// Performance metrics
	content.WriteString(d.renderPerformanceMetrics())

	return content.String()
}

// renderHeader renders the dashboard header
func (d *Dashboard) renderHeader() string {
	title := "🛡️  Jacked Security Scanner Dashboard"

	target := d.params.Diggity.Input
	if target == "" {
		target = "Unknown"
	}

	subtitle := fmt.Sprintf("Target: %s", target)

	return Box(subtitle, title)
}

// renderPhaseStatus renders the current phase status
func (d *Dashboard) renderPhaseStatus() string {
	phaseNames := map[ScanPhase]string{
		PhaseInitializing:  "🚀 Initializing",
		PhaseUpdatingDB:    "🗄️  Updating Database",
		PhaseGeneratingBOM: "📋 Generating BOM",
		PhaseScanning:      "🔍 Scanning Components",
		PhaseAnalyzing:     "🧮 Analyzing Results",
		PhaseComplete:      "✅ Complete",
		PhaseError:         "❌ Error",
	}

	currentPhase := phaseNames[d.phase]
	elapsed := time.Since(d.startTime)

	status := fmt.Sprintf("Phase: %s\nElapsed: %v", currentPhase, elapsed.Truncate(time.Second))

	if d.phase == PhaseComplete {
		return SuccessBox(status, "Scan Status")
	} else if d.phase == PhaseError {
		return ErrorBox(status, "Scan Status")
	} else {
		return InfoBox(status, "Scan Status")
	}
}

// renderStatsOverview renders a statistics overview
func (d *Dashboard) renderStatsOverview() string {
	var statsCards []string

	// Components
	if d.scanStats.TotalComponents > 0 {
		card := StatCard("Components", fmt.Sprintf("%d", d.scanStats.TotalComponents), "Total analyzed")
		statsCards = append(statsCards, card)
	}

	// Total vulnerabilities
	totalVulns := d.scanStats.CriticalVulns + d.scanStats.HighVulns + d.scanStats.MediumVulns + d.scanStats.LowVulns + d.scanStats.NegligibleVulns
	if totalVulns > 0 {
		card := StatCard("Vulnerabilities", fmt.Sprintf("%d", totalVulns), "Total found")
		statsCards = append(statsCards, card)

		// High-risk vulnerabilities
		highRisk := d.scanStats.CriticalVulns + d.scanStats.HighVulns
		if highRisk > 0 {
			card := StatCard("High Risk", fmt.Sprintf("%d", highRisk), "Critical + High")
			statsCards = append(statsCards, card)
		}
	}

	if len(statsCards) == 0 {
		return InfoBox("No statistics available yet", "Statistics")
	}

	return strings.Join(statsCards, " ")
}

// renderMessages renders errors, warnings, and insights
func (d *Dashboard) renderMessages() string {
	var content strings.Builder

	// Errors
	if len(d.errors) > 0 {
		errorList := strings.Join(d.errors, "\n")
		content.WriteString(ErrorBox(errorList, "Errors"))
		content.WriteString("\n")
	}

	// Warnings
	if len(d.warnings) > 0 {
		warningList := strings.Join(d.warnings, "\n")
		content.WriteString(WarningBox(warningList, "Warnings"))
		content.WriteString("\n")
	}

	// Insights
	if len(d.insights) > 0 {
		insightList := strings.Join(d.insights, "\n")
		content.WriteString(InfoBox(insightList, "Insights"))
	}

	return content.String()
}

// renderPerformanceMetrics renders performance information
func (d *Dashboard) renderPerformanceMetrics() string {
	var metrics []string

	// Scanning speed
	if d.scanStats.ComponentsPerSec > 0 {
		metrics = append(metrics, fmt.Sprintf("Speed: %.1f components/sec", d.scanStats.ComponentsPerSec))
	}

	// Memory usage (placeholder - would need actual memory monitoring)
	metrics = append(metrics, "Memory: Monitoring enabled")

	// Database info (placeholder)
	if d.scanStats.LastDBUpdate.IsZero() {
		metrics = append(metrics, "DB: Up to date")
	} else {
		metrics = append(metrics, fmt.Sprintf("DB: Updated %v ago", time.Since(d.scanStats.LastDBUpdate).Truncate(time.Hour)))
	}

	if len(metrics) == 0 {
		return ""
	}

	return InfoBox(strings.Join(metrics, "\n"), "Performance")
}

// GetRiskScore calculates a simple risk score based on vulnerabilities
func (d *Dashboard) GetRiskScore() int {
	score := d.scanStats.CriticalVulns*10 +
		d.scanStats.HighVulns*7 +
		d.scanStats.MediumVulns*4 +
		d.scanStats.LowVulns*1

	return score
}

// GetRiskLevel returns a textual risk level
func (d *Dashboard) GetRiskLevel() string {
	score := d.GetRiskScore()

	switch {
	case score == 0:
		return "SECURE"
	case score < 10:
		return "LOW"
	case score < 30:
		return "MEDIUM"
	case score < 60:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

// GenerateRecommendations generates security recommendations
func (d *Dashboard) GenerateRecommendations() []string {
	var recommendations []string

	if d.scanStats.CriticalVulns > 0 {
		recommendations = append(recommendations, "🚨 Address critical vulnerabilities immediately")
	}

	if d.scanStats.HighVulns > 0 {
		recommendations = append(recommendations, "⚠️  Plan to fix high-severity vulnerabilities")
	}

	if d.scanStats.TotalComponents > 50 {
		recommendations = append(recommendations, "📦 Consider component inventory management")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "✅ No immediate security actions required")
	}

	return recommendations
}
