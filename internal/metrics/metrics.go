package metrics

import (
	"fmt"
	"sync"
	"time"
)

// ScanMetrics tracks performance metrics for vulnerability scanning
type ScanMetrics struct {
	mutex               sync.RWMutex
	totalScans          int64
	totalDuration       time.Duration
	componentCounts     []int
	vulnerabilityCounts []int
	scannerMetrics      map[string]*ScannerMetrics
	cacheHits           int64
	cacheMisses         int64
}

// ScannerMetrics tracks metrics for individual scanners
type ScannerMetrics struct {
	Name            string
	ExecutionCount  int64
	TotalDuration   time.Duration
	AverageDuration time.Duration
	ErrorCount      int64
	VulnCount       int64
}

// Global metrics instance
var globalMetrics = &ScanMetrics{
	scannerMetrics: make(map[string]*ScannerMetrics),
}

// GetGlobalMetrics returns the global metrics instance
func GetGlobalMetrics() *ScanMetrics {
	return globalMetrics
}

// RecordScan records metrics for a complete scan operation
func (m *ScanMetrics) RecordScan(duration time.Duration, componentCount int, vulnCount int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.totalScans++
	m.totalDuration += duration
	m.componentCounts = append(m.componentCounts, componentCount)
	m.vulnerabilityCounts = append(m.vulnerabilityCounts, vulnCount)

	// Keep only last 100 scans for rolling averages
	if len(m.componentCounts) > 100 {
		m.componentCounts = m.componentCounts[1:]
		m.vulnerabilityCounts = m.vulnerabilityCounts[1:]
	}
}

// RecordScannerExecution records metrics for individual scanner execution
func (m *ScanMetrics) RecordScannerExecution(scannerName string, duration time.Duration, vulnCount int, hasError bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.scannerMetrics[scannerName] == nil {
		m.scannerMetrics[scannerName] = &ScannerMetrics{
			Name: scannerName,
		}
	}

	scanner := m.scannerMetrics[scannerName]
	scanner.ExecutionCount++
	scanner.TotalDuration += duration
	scanner.AverageDuration = scanner.TotalDuration / time.Duration(scanner.ExecutionCount)
	scanner.VulnCount += int64(vulnCount)

	if hasError {
		scanner.ErrorCount++
	}
}

// RecordCacheHit records a cache hit
func (m *ScanMetrics) RecordCacheHit() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.cacheHits++
}

// RecordCacheMiss records a cache miss
func (m *ScanMetrics) RecordCacheMiss() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.cacheMisses++
}

// GetSummary returns a summary of all metrics
func (m *ScanMetrics) GetSummary() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	summary := make(map[string]interface{})

	// Overall metrics
	summary["total_scans"] = m.totalScans
	summary["total_duration"] = m.totalDuration.String()

	if m.totalScans > 0 {
		summary["average_scan_duration"] = (m.totalDuration / time.Duration(m.totalScans)).String()
	}

	// Component metrics
	if len(m.componentCounts) > 0 {
		summary["average_components_per_scan"] = m.calculateAverage(m.componentCounts)
		summary["max_components_per_scan"] = m.calculateMax(m.componentCounts)
	}

	// Vulnerability metrics
	if len(m.vulnerabilityCounts) > 0 {
		summary["average_vulnerabilities_per_scan"] = m.calculateAverage(m.vulnerabilityCounts)
		summary["max_vulnerabilities_per_scan"] = m.calculateMax(m.vulnerabilityCounts)
	}

	// Cache metrics
	totalCacheRequests := m.cacheHits + m.cacheMisses
	if totalCacheRequests > 0 {
		summary["cache_hit_rate"] = float64(m.cacheHits) / float64(totalCacheRequests)
		summary["cache_hits"] = m.cacheHits
		summary["cache_misses"] = m.cacheMisses
	}

	// Scanner-specific metrics
	scannerSummaries := make(map[string]interface{})
	for name, scanner := range m.scannerMetrics {
		scannerSummaries[name] = map[string]interface{}{
			"execution_count":       scanner.ExecutionCount,
			"total_duration":        scanner.TotalDuration.String(),
			"average_duration":      scanner.AverageDuration.String(),
			"error_count":           scanner.ErrorCount,
			"total_vulnerabilities": scanner.VulnCount,
		}

		if scanner.ExecutionCount > 0 {
			scannerSummaries[name].(map[string]interface{})["error_rate"] =
				float64(scanner.ErrorCount) / float64(scanner.ExecutionCount)
			scannerSummaries[name].(map[string]interface{})["avg_vulns_per_scan"] =
				float64(scanner.VulnCount) / float64(scanner.ExecutionCount)
		}
	}
	summary["scanners"] = scannerSummaries

	return summary
}

// GetFormattedSummary returns a human-readable summary
func (m *ScanMetrics) GetFormattedSummary() string {
	summary := m.GetSummary()

	result := "=== Jacked Performance Metrics ===\n"

	if totalScans, ok := summary["total_scans"].(int64); ok && totalScans > 0 {
		result += fmt.Sprintf("Total Scans: %d\n", totalScans)

		if avgDuration, ok := summary["average_scan_duration"].(string); ok {
			result += fmt.Sprintf("Average Scan Duration: %s\n", avgDuration)
		}

		if avgComponents, ok := summary["average_components_per_scan"].(float64); ok {
			result += fmt.Sprintf("Average Components per Scan: %.1f\n", avgComponents)
		}

		if avgVulns, ok := summary["average_vulnerabilities_per_scan"].(float64); ok {
			result += fmt.Sprintf("Average Vulnerabilities per Scan: %.1f\n", avgVulns)
		}

		if cacheHitRate, ok := summary["cache_hit_rate"].(float64); ok {
			result += fmt.Sprintf("Cache Hit Rate: %.2f%%\n", cacheHitRate*100)
		}

		result += "\n--- Scanner Performance ---\n"
		if scanners, ok := summary["scanners"].(map[string]interface{}); ok {
			for name, metrics := range scanners {
				if scannerMetrics, ok := metrics.(map[string]interface{}); ok {
					result += fmt.Sprintf("%s:\n", name)
					if execCount, ok := scannerMetrics["execution_count"].(int64); ok {
						result += fmt.Sprintf("  Executions: %d\n", execCount)
					}
					if avgDuration, ok := scannerMetrics["average_duration"].(string); ok {
						result += fmt.Sprintf("  Avg Duration: %s\n", avgDuration)
					}
					if errorRate, ok := scannerMetrics["error_rate"].(float64); ok {
						result += fmt.Sprintf("  Error Rate: %.2f%%\n", errorRate*100)
					}
				}
			}
		}
	} else {
		result += "No scan metrics available yet.\n"
	}

	return result
}

// Reset clears all metrics
func (m *ScanMetrics) Reset() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.totalScans = 0
	m.totalDuration = 0
	m.componentCounts = nil
	m.vulnerabilityCounts = nil
	m.scannerMetrics = make(map[string]*ScannerMetrics)
	m.cacheHits = 0
	m.cacheMisses = 0
}

// Helper functions
func (m *ScanMetrics) calculateAverage(values []int) float64 {
	if len(values) == 0 {
		return 0
	}

	sum := 0
	for _, v := range values {
		sum += v
	}

	return float64(sum) / float64(len(values))
}

func (m *ScanMetrics) calculateMax(values []int) int {
	if len(values) == 0 {
		return 0
	}

	max := values[0]
	for _, v := range values[1:] {
		if v > max {
			max = v
		}
	}

	return max
}

// GetTopPerformingScanners returns scanners sorted by performance
func (m *ScanMetrics) GetTopPerformingScanners(limit int) []ScannerMetrics {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	scanners := make([]ScannerMetrics, 0, len(m.scannerMetrics))
	for _, scanner := range m.scannerMetrics {
		scanners = append(scanners, *scanner)
	}

	// Sort by average duration (ascending - faster is better)
	for i := 0; i < len(scanners)-1; i++ {
		for j := i + 1; j < len(scanners); j++ {
			if scanners[i].AverageDuration > scanners[j].AverageDuration {
				scanners[i], scanners[j] = scanners[j], scanners[i]
			}
		}
	}

	if limit > 0 && limit < len(scanners) {
		scanners = scanners[:limit]
	}

	return scanners
}
