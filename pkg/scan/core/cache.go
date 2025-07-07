package core

import (
	"sync"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
)

// MemoryCache provides in-memory caching for scan results
type MemoryCache struct {
	cache      map[string]cacheEntry
	mutex      sync.RWMutex
	defaultTTL time.Duration
}

type cacheEntry struct {
	vulnerabilities []cyclonedx.Vulnerability
	expireAt        time.Time
}

// NewMemoryCache creates a new memory-based cache
func NewMemoryCache(defaultTTL time.Duration) *MemoryCache {
	return &MemoryCache{
		cache:      make(map[string]cacheEntry),
		defaultTTL: defaultTTL,
	}
}

// Get retrieves vulnerabilities from cache
func (c *MemoryCache) Get(key string) ([]cyclonedx.Vulnerability, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.cache[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expireAt) {
		// Entry has expired, remove it
		c.mutex.RUnlock()
		c.mutex.Lock()
		delete(c.cache, key)
		c.mutex.Unlock()
		c.mutex.RLock()
		return nil, false
	}

	return entry.vulnerabilities, true
}

// Set stores vulnerabilities in cache with specified TTL
func (c *MemoryCache) Set(key string, vulnerabilities []cyclonedx.Vulnerability, ttl time.Duration) {
	if ttl == 0 {
		ttl = c.defaultTTL
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache[key] = cacheEntry{
		vulnerabilities: vulnerabilities,
		expireAt:        time.Now().Add(ttl),
	}
}

// Clear removes all entries from cache
func (c *MemoryCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache = make(map[string]cacheEntry)
}

// Size returns the number of entries in cache
func (c *MemoryCache) Size() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return len(c.cache)
}
