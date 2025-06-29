package matcher

import (
	"sync/atomic"
	"time"

	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// progressMonitor tracks scanning progress
type progressMonitor struct {
	PackagesProcessed *atomicCounter
	MatchesDiscovered *atomicCounter
	Fixed             *atomicCounter
	Ignored           *atomicCounter
	Dropped           *atomicCounter
	BySeverity        map[Severity]*atomicCounter
	enabled           bool
	startTime         time.Time
}

// atomicCounter provides thread-safe counter operations
type atomicCounter struct {
	count int64
}

func newAtomicCounter() *atomicCounter {
	return &atomicCounter{}
}

func (c *atomicCounter) Increment() {
	atomic.AddInt64(&c.count, 1)
}

func (c *atomicCounter) Add(value int64) {
	atomic.AddInt64(&c.count, value)
}

func (c *atomicCounter) Set(value int64) {
	atomic.StoreInt64(&c.count, value)
}

func (c *atomicCounter) Current() int64 {
	return atomic.LoadInt64(&c.count)
}

func (c *atomicCounter) SetCompleted() {
	// Mark as completed (implementation can be extended)
}

func (c *atomicCounter) SetError(err error) {
	// Handle error state (implementation can be extended)
}

// newProgressMonitor creates a new progress monitor
func newProgressMonitor(packageCount int, enabled bool) *progressMonitor {
	monitor := &progressMonitor{
		PackagesProcessed: newAtomicCounter(),
		MatchesDiscovered: newAtomicCounter(),
		Fixed:             newAtomicCounter(),
		Ignored:           newAtomicCounter(),
		Dropped:           newAtomicCounter(),
		BySeverity:        make(map[Severity]*atomicCounter),
		enabled:           enabled,
		startTime:         time.Now(),
	}

	// Initialize severity counters
	severities := []Severity{matchertypes.CriticalSeverity, matchertypes.HighSeverity, matchertypes.MediumSeverity, matchertypes.LowSeverity, matchertypes.UnknownSeverity}
	for _, severity := range severities {
		monitor.BySeverity[severity] = newAtomicCounter()
	}

	return monitor
}

// SetCompleted marks the monitoring as completed
func (m *progressMonitor) SetCompleted() {
	if !m.enabled {
		return
	}

	m.PackagesProcessed.SetCompleted()
	m.MatchesDiscovered.SetCompleted()
	m.Fixed.SetCompleted()
	m.Ignored.SetCompleted()
	m.Dropped.SetCompleted()

	for _, counter := range m.BySeverity {
		counter.SetCompleted()
	}
}

// GetElapsedTime returns the elapsed time since monitoring started
func (m *progressMonitor) GetElapsedTime() time.Duration {
	return time.Since(m.startTime)
}

// GetStats returns current statistics
func (m *progressMonitor) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"packages_processed": m.PackagesProcessed.Current(),
		"matches_discovered": m.MatchesDiscovered.Current(),
		"fixed":              m.Fixed.Current(),
		"ignored":            m.Ignored.Current(),
		"dropped":            m.Dropped.Current(),
		"elapsed_time":       m.GetElapsedTime().String(),
	}

	severityStats := make(map[string]int64)
	for severity, counter := range m.BySeverity {
		severityStats[string(severity)] = counter.Current()
	}
	stats["by_severity"] = severityStats

	return stats
}
