package core

import (
	"sync"
	"time"
)

// SimpleMetricsCollector provides basic metrics collection
type SimpleMetricsCollector struct {
	mutex       sync.RWMutex
	scanMetrics map[string]*ScannerMetrics
	errors      map[string][]error
}

// ScannerMetrics holds metrics for a specific scanner
type ScannerMetrics struct {
	TotalScans      int           `json:"total_scans"`
	TotalDuration   time.Duration `json:"total_duration"`
	AverageDuration time.Duration `json:"average_duration"`
	TotalComponents int           `json:"total_components"`
	TotalVulns      int           `json:"total_vulnerabilities"`
	LastScan        time.Time     `json:"last_scan"`
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *SimpleMetricsCollector {
	return &SimpleMetricsCollector{
		scanMetrics: make(map[string]*ScannerMetrics),
		errors:      make(map[string][]error),
	}
}

// RecordScan records metrics for a scan operation
func (m *SimpleMetricsCollector) RecordScan(scannerType string, duration time.Duration, componentCount, vulnCount int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	metrics, exists := m.scanMetrics[scannerType]
	if !exists {
		metrics = &ScannerMetrics{}
		m.scanMetrics[scannerType] = metrics
	}

	metrics.TotalScans++
	metrics.TotalDuration += duration
	metrics.AverageDuration = metrics.TotalDuration / time.Duration(metrics.TotalScans)
	metrics.TotalComponents += componentCount
	metrics.TotalVulns += vulnCount
	metrics.LastScan = time.Now()
}

// RecordAnalysis records metrics for an analysis operation
func (m *SimpleMetricsCollector) RecordAnalysis(analyzerType string, duration time.Duration, componentCount, vulnCount int) {
	// For simplicity, treat analysis the same as scans
	m.RecordScan(analyzerType, duration, componentCount, vulnCount)
}

// RecordError records an error for a scanner
func (m *SimpleMetricsCollector) RecordError(scannerType string, err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.errors[scannerType] = append(m.errors[scannerType], err)

	// Keep only the last 10 errors per scanner
	if len(m.errors[scannerType]) > 10 {
		m.errors[scannerType] = m.errors[scannerType][1:]
	}
}

// GetMetrics returns all collected metrics
func (m *SimpleMetricsCollector) GetMetrics() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	result := make(map[string]interface{})
	result["scanners"] = m.scanMetrics

	errorCounts := make(map[string]int)
	for scannerType, errors := range m.errors {
		errorCounts[scannerType] = len(errors)
	}
	result["error_counts"] = errorCounts

	return result
}
