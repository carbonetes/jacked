package metrics

import (
	"testing"
	"time"
)

// Test constants
const (
	testScannerName   = "test-scanner"
	testScannerName2  = "test-scanner-2"
	testDuration      = 100 * time.Millisecond
	testVulnCount     = 5
	expectedZeroValue = 0
)

// TestGetGlobalMetrics tests global metrics instance creation
func TestGetGlobalMetrics(t *testing.T) {
	metrics1 := GetGlobalMetrics()
	metrics2 := GetGlobalMetrics()

	if metrics1 == nil {
		t.Fatal("Expected global metrics instance, got nil")
	}

	if metrics1 != metrics2 {
		t.Error("Expected global metrics to return same instance (singleton pattern)")
	}
}

// TestRecordScan tests scan recording functionality
func TestRecordScan(t *testing.T) {
	metrics := GetGlobalMetrics()
	metrics.Reset() // Start with clean state

	componentCount := 10
	vulnCount := 3
	duration := testDuration

	metrics.RecordScan(duration, componentCount, vulnCount)

	summary := metrics.GetSummary()

	if summary == nil {
		t.Fatal("Expected summary to be non-nil")
	}

	// Check that scan was recorded
	if len(metrics.componentCounts) != 1 {
		t.Errorf("Expected 1 component count recorded, got %d", len(metrics.componentCounts))
	}

	if len(metrics.vulnerabilityCounts) != 1 {
		t.Errorf("Expected 1 vulnerability count recorded, got %d", len(metrics.vulnerabilityCounts))
	}

	if metrics.totalScans != 1 {
		t.Errorf("Expected total scans to be 1, got %d", metrics.totalScans)
	}
}

// TestRecordScannerExecution tests individual scanner execution recording
func TestRecordScannerExecution(t *testing.T) {
	metrics := GetGlobalMetrics()
	metrics.Reset()

	duration := testDuration
	vulnCount := testVulnCount
	hasError := false

	metrics.RecordScannerExecution(testScannerName, duration, vulnCount, hasError)

	// Check that scanner execution was recorded
	if _, exists := metrics.scannerMetrics[testScannerName]; !exists {
		t.Errorf("Expected scanner metrics for %s to be recorded", testScannerName)
	}
}

// TestRecordScannerExecutionWithError tests scanner execution with error
func TestRecordScannerExecutionWithError(t *testing.T) {
	metrics := GetGlobalMetrics()
	metrics.Reset()

	duration := testDuration
	vulnCount := expectedZeroValue // No vulnerabilities when there's an error
	hasError := true

	metrics.RecordScannerExecution(testScannerName, duration, vulnCount, hasError)

	scannerStats, exists := metrics.scannerMetrics[testScannerName]
	if !exists {
		t.Fatalf("Expected scanner metrics for %s to be recorded", testScannerName)
	}

	if scannerStats.ErrorCount != 1 {
		t.Errorf("Expected error count to be 1, got %d", scannerStats.ErrorCount)
	}
}

// TestRecordCacheOperations tests cache hit/miss recording
func TestRecordCacheOperations(t *testing.T) {
	metrics := GetGlobalMetrics()
	metrics.Reset()

	// Record cache hits
	metrics.RecordCacheHit()
	metrics.RecordCacheHit()

	// Record cache miss
	metrics.RecordCacheMiss()

	if metrics.cacheHits != 2 {
		t.Errorf("Expected 2 cache hits, got %d", metrics.cacheHits)
	}

	if metrics.cacheMisses != 1 {
		t.Errorf("Expected 1 cache miss, got %d", metrics.cacheMisses)
	}
}

// TestGetSummary tests metrics summary generation
func TestGetSummary(t *testing.T) {
	metrics := GetGlobalMetrics()
	metrics.Reset()

	// Record some test data
	metrics.RecordScan(testDuration, 10, 3)
	metrics.RecordScan(200*time.Millisecond, 20, 5)
	metrics.RecordScannerExecution(testScannerName, testDuration, testVulnCount, false)
	metrics.RecordCacheHit()
	metrics.RecordCacheMiss()

	summary := metrics.GetSummary()

	if summary == nil {
		t.Fatal("Expected summary to be non-nil")
	}

	// Verify summary contains expected data
	if totalScans, ok := summary["total_scans"].(int64); !ok || totalScans != 2 {
		t.Errorf("Expected total_scans to be 2, got %v", summary["total_scans"])
	}

	if cacheHits, ok := summary["cache_hits"].(int64); !ok || cacheHits != 1 {
		t.Errorf("Expected cache_hits to be 1, got %v", summary["cache_hits"])
	}

	if cacheMisses, ok := summary["cache_misses"].(int64); !ok || cacheMisses != 1 {
		t.Errorf("Expected cache_misses to be 1, got %v", summary["cache_misses"])
	}
}

// TestGetFormattedSummary tests formatted summary output
func TestGetFormattedSummary(t *testing.T) {
	metrics := GetGlobalMetrics()
	metrics.Reset()

	// Record some test data
	metrics.RecordScan(testDuration, 10, 3)
	metrics.RecordScannerExecution(testScannerName, testDuration, testVulnCount, false)

	formatted := metrics.GetFormattedSummary()

	if formatted == "" {
		t.Error("Expected non-empty formatted summary")
	}

	// Check that formatted summary contains expected content
	if !contains(formatted, "Total Scans") {
		t.Error("Expected formatted summary to contain 'Total Scans'")
	}
}

// TestReset tests metrics reset functionality
func TestReset(t *testing.T) {
	metrics := GetGlobalMetrics()

	// Record some data
	metrics.RecordScan(testDuration, 10, 3)
	metrics.RecordScannerExecution(testScannerName, testDuration, testVulnCount, false)
	metrics.RecordCacheHit()

	// Reset metrics
	metrics.Reset()

	// Verify everything is reset
	if len(metrics.componentCounts) != expectedZeroValue {
		t.Errorf("Expected component counts to be reset, got %d entries", len(metrics.componentCounts))
	}

	if len(metrics.vulnerabilityCounts) != expectedZeroValue {
		t.Errorf("Expected vulnerability counts to be reset, got %d entries", len(metrics.vulnerabilityCounts))
	}

	if len(metrics.scannerMetrics) != expectedZeroValue {
		t.Errorf("Expected scanner metrics to be reset, got %d entries", len(metrics.scannerMetrics))
	}

	if metrics.cacheHits != expectedZeroValue {
		t.Errorf("Expected cache hits to be reset, got %d", metrics.cacheHits)
	}

	if metrics.cacheMisses != expectedZeroValue {
		t.Errorf("Expected cache misses to be reset, got %d", metrics.cacheMisses)
	}

	if metrics.totalScans != expectedZeroValue {
		t.Errorf("Expected total scans to be reset, got %d", metrics.totalScans)
	}
}

// TestMultipleScannerExecutions tests recording from multiple scanners
func TestMultipleScannerExecutions(t *testing.T) {
	metrics := GetGlobalMetrics()
	metrics.Reset()

	// Record executions from different scanners
	metrics.RecordScannerExecution(testScannerName, testDuration, testVulnCount, false)
	metrics.RecordScannerExecution(testScannerName2, 200*time.Millisecond, 3, false)
	metrics.RecordScannerExecution(testScannerName, 150*time.Millisecond, 2, false) // Second execution from first scanner

	if len(metrics.scannerMetrics) != 2 {
		t.Errorf("Expected 2 different scanners recorded, got %d", len(metrics.scannerMetrics))
	}

	scanner1Stats := metrics.scannerMetrics[testScannerName]
	if scanner1Stats.ExecutionCount != 2 {
		t.Errorf("Expected scanner1 execution count to be 2, got %d", scanner1Stats.ExecutionCount)
	}

	scanner2Stats := metrics.scannerMetrics[testScannerName2]
	if scanner2Stats.ExecutionCount != 1 {
		t.Errorf("Expected scanner2 execution count to be 1, got %d", scanner2Stats.ExecutionCount)
	}
}

// TestConcurrentAccess tests thread safety of metrics recording
func TestConcurrentAccess(t *testing.T) {
	metrics := GetGlobalMetrics()
	metrics.Reset()

	// Run concurrent operations
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			metrics.RecordScan(testDuration, 10, 2)
			metrics.RecordCacheHit()
			metrics.RecordCacheMiss()
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify that all operations were recorded
	if len(metrics.componentCounts) != 10 {
		t.Errorf("Expected 10 component counts, got %d", len(metrics.componentCounts))
	}

	if metrics.cacheHits != 10 {
		t.Errorf("Expected 10 cache hits, got %d", metrics.cacheHits)
	}

	if metrics.cacheMisses != 10 {
		t.Errorf("Expected 10 cache misses, got %d", metrics.cacheMisses)
	}

	if metrics.totalScans != 10 {
		t.Errorf("Expected 10 total scans, got %d", metrics.totalScans)
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				containsAtIndex(s, substr))))
}

func containsAtIndex(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Benchmark tests
func BenchmarkRecordScan(b *testing.B) {
	metrics := GetGlobalMetrics()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.RecordScan(testDuration, 10, 3)
	}
}

func BenchmarkRecordScannerExecution(b *testing.B) {
	metrics := GetGlobalMetrics()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.RecordScannerExecution(testScannerName, testDuration, testVulnCount, false)
	}
}

func BenchmarkGetSummary(b *testing.B) {
	metrics := GetGlobalMetrics()
	metrics.Reset()

	// Add some test data
	for i := 0; i < 100; i++ {
		metrics.RecordScan(testDuration, 10, 3)
		metrics.RecordScannerExecution(testScannerName, testDuration, testVulnCount, false)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = metrics.GetSummary()
	}
}
