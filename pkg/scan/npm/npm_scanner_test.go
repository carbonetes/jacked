package npm

import (
	"testing"

	"github.com/carbonetes/jacked/internal/db"
)

func TestNewScanner(t *testing.T) {
	store := db.Store{}
	scanner := NewScanner(store)

	if scanner == nil {
		t.Fatal("Expected scanner to be created, got nil")
	}
}

func TestScanWithNilBOM(t *testing.T) {
	store := db.Store{}
	scanner := NewScanner(store)

	vulnerabilities, err := scanner.Scan(nil)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if len(vulnerabilities) != 0 {
		t.Errorf("Expected 0 vulnerabilities, got %d", len(vulnerabilities))
	}
}
