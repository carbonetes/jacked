package scan

import (
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
)

// TestNewManager tests the creation of a new scan manager
func TestNewManager(t *testing.T) {
	store := &db.Store{}
	manager := NewManager(*store)

	if manager == nil {
		t.Fatal("Expected manager to be created, got nil")
	}

	if manager.engine == nil {
		t.Fatal("Expected engine to be created, got nil")
	}
}

// TestManagerSetters tests the fluent interface setters
func TestManagerSetters(t *testing.T) {
	store := &db.Store{}
	manager := NewManager(*store)

	// Test SetCaching
	result := manager.SetCaching(false)
	if result != manager {
		t.Error("Expected SetCaching to return the same manager instance")
	}

	// Test SetConcurrency
	result = manager.SetConcurrency(8)
	if result != manager {
		t.Error("Expected SetConcurrency to return the same manager instance")
	}

	// Test SetTimeout
	timeout := 10 * time.Minute
	result = manager.SetTimeout(timeout)
	if result != manager {
		t.Error("Expected SetTimeout to return the same manager instance")
	}
}

// TestManagerRunWithEmptyBOM tests scanning with empty BOM
func TestManagerRunWithEmptyBOM(t *testing.T) {
	store := &db.Store{}
	manager := NewManager(*store)

	tests := []struct {
		name string
		bom  *cyclonedx.BOM
	}{
		{"nil BOM", nil},
		{"nil components", &cyclonedx.BOM{}},
		{"empty components", &cyclonedx.BOM{Components: &[]cyclonedx.Component{}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulnerabilities, err := manager.Run(tt.bom)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
			if len(vulnerabilities) != 0 {
				t.Errorf("Expected 0 vulnerabilities, got %d", len(vulnerabilities))
			}
		})
	}
}

// TestManagerRunWithComponents tests scanning with actual components
func TestManagerRunWithComponents(t *testing.T) {
	store := &db.Store{}
	manager := NewManager(*store)

	// Create test BOM with components
	component := cyclonedx.Component{
		Name:    "test-component",
		Version: "1.0.0",
		Type:    cyclonedx.ComponentTypeLibrary,
	}
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{component},
	}

	vulnerabilities, err := manager.Run(bom)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Since we're using a real store that likely returns empty results in test environment,
	// we expect 0 or more vulnerabilities
	if vulnerabilities == nil {
		t.Error("Expected vulnerabilities slice to be non-nil")
	}
}

// TestManagerMetrics tests metrics collection
func TestManagerMetrics(t *testing.T) {
	store := &db.Store{}
	manager := NewManager(*store)

	metrics := manager.GetMetrics()
	if metrics == nil {
		t.Error("Expected metrics to be returned")
	}
}

// TestManagerCacheStats tests cache statistics
func TestManagerCacheStats(t *testing.T) {
	store := &db.Store{}
	manager := NewManager(*store)

	stats := manager.GetCacheStats()
	if stats == nil {
		t.Error("Expected cache stats to be returned")
	}
}
