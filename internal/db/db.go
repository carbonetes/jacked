package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path"
	"runtime"
	"sync"
	"time"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/model"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
	_ "modernc.org/sqlite"
)

const (
	driver   = "sqlite"
	filename = "jacked"
	filetype = "db"
)

var (
	userCache, _ = os.UserCacheDir()
	db           *bun.DB
	dbDirectory  = path.Join(userCache, filename)
	dbFile       = filename + "." + filetype
	dbFilepath   = os.Getenv("JACKED_DB")

	// Connection pool settings
	maxOpenConns = runtime.NumCPU() * 2
	maxIdleConns = runtime.NumCPU()

	// Cache for frequently accessed vulnerabilities
	vulnCache     = make(map[string]*[]model.Vulnerability)
	cacheMutex    sync.RWMutex
	cacheTimeout  = 15 * time.Minute
	lastCacheTime = make(map[string]time.Time)
)

type Store struct{}

func init() {
	if dbFilepath == "" {
		dbFilepath = path.Join(dbDirectory, dbFile)
		os.Setenv("JACKED_DB", dbFilepath)
	}
}

// Load initializes the database connection with optimized settings
func Load() {
	sqldb, err := sql.Open(sqliteshim.ShimName, dbFilepath)
	if err != nil {
		log.Fatalf("error establishing database connection: %v", err)
	}

	// Configure connection pool for better performance
	sqldb.SetMaxOpenConns(maxOpenConns)
	sqldb.SetMaxIdleConns(maxIdleConns)
	sqldb.SetConnMaxLifetime(30 * time.Minute)
	sqldb.SetConnMaxIdleTime(5 * time.Minute)

	db = bun.NewDB(sqldb, sqlitedialect.New())

	// Test database connection
	if err := db.Ping(); err != nil {
		log.Fatalf("error pinging database: %v", err)
	}

	// Enable performance optimizations
	optimizeDatabase()

	log.Debug("Database connection pool initialized with optimizations")
}

func GetDB() *bun.DB {
	return db
}

// optimizeDatabase applies SQLite performance optimizations
func optimizeDatabase() {
	optimizations := []string{
		"PRAGMA journal_mode = WAL",    // Write-Ahead Logging for better concurrency
		"PRAGMA synchronous = NORMAL",  // Balance between safety and performance
		"PRAGMA cache_size = -64000",   // 64MB cache
		"PRAGMA temp_store = MEMORY",   // Store temp tables in memory
		"PRAGMA mmap_size = 268435456", // 256MB memory map
		"PRAGMA optimize",              // Optimize query planner
	}

	for _, pragma := range optimizations {
		if _, err := db.Exec(pragma); err != nil {
			log.Debugf("Failed to apply optimization %s: %v", pragma, err)
		}
	}
}

// getCachedVulnerabilities retrieves vulnerabilities from cache if available and fresh
func getCachedVulnerabilities(cacheKey string) (*[]model.Vulnerability, bool) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	if data, exists := vulnCache[cacheKey]; exists {
		if lastUpdate, timeExists := lastCacheTime[cacheKey]; timeExists {
			if time.Since(lastUpdate) < cacheTimeout {
				return data, true
			}
		}
	}

	return nil, false
}

// setCachedVulnerabilities stores vulnerabilities in cache
func setCachedVulnerabilities(cacheKey string, data *[]model.Vulnerability) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	vulnCache[cacheKey] = data
	lastCacheTime[cacheKey] = time.Now()
}

// BatchVulnerabilityLookup performs optimized batch vulnerability lookups
func (s *Store) BatchVulnerabilityLookup(packages []string, source string) map[string]*[]model.Vulnerability {
	if len(packages) == 0 {
		return make(map[string]*[]model.Vulnerability)
	}

	results := make(map[string]*[]model.Vulnerability)
	uncachedPackages := make([]string, 0, len(packages))

	// Check cache first
	for _, pkg := range packages {
		cacheKey := fmt.Sprintf("%s:%s", source, pkg)
		if cached, found := getCachedVulnerabilities(cacheKey); found {
			results[pkg] = cached
		} else {
			uncachedPackages = append(uncachedPackages, pkg)
		}
	}

	// Batch query for uncached packages
	if len(uncachedPackages) > 0 {
		batchResults := s.batchQueryVulnerabilities(uncachedPackages, source)

		// Cache and merge results
		for pkg, vulns := range batchResults {
			cacheKey := fmt.Sprintf("%s:%s", source, pkg)
			setCachedVulnerabilities(cacheKey, vulns)
			results[pkg] = vulns
		}
	}

	return results
}

// batchQueryVulnerabilities performs optimized batch database queries
func (s *Store) batchQueryVulnerabilities(packages []string, source string) map[string]*[]model.Vulnerability {
	if len(packages) == 0 {
		return make(map[string]*[]model.Vulnerability)
	}

	vulnerabilities := make([]model.Vulnerability, 0)
	query := db.NewSelect().
		Model(&vulnerabilities).
		Where("package IN (?) AND source = ?", bun.In(packages), source)

	if err := query.Scan(context.Background()); err != nil {
		log.Debugf("Error in batch vulnerability lookup: %v", err)
		return make(map[string]*[]model.Vulnerability)
	}

	// Group results by package
	results := make(map[string]*[]model.Vulnerability)
	for _, pkg := range packages {
		results[pkg] = &[]model.Vulnerability{}
	}

	for _, vuln := range vulnerabilities {
		if packageVulns, exists := results[vuln.Package]; exists {
			*packageVulns = append(*packageVulns, vuln)
		}
	}

	return results
}

// ClearCache manually clears the vulnerability cache
func ClearCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	vulnCache = make(map[string]*[]model.Vulnerability)
	lastCacheTime = make(map[string]time.Time)

	log.Debug("Vulnerability cache cleared")
}

// GetCacheStats returns cache statistics for monitoring
func GetCacheStats() map[string]interface{} {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	return map[string]interface{}{
		"cache_size":     len(vulnCache),
		"cache_timeout":  cacheTimeout.String(),
		"max_open_conns": maxOpenConns,
		"max_idle_conns": maxIdleConns,
	}
}

// GetVulnerabilityByID retrieves a vulnerability by its CVE ID from the database
func (s *Store) GetVulnerabilityByID(id string) (*model.Vulnerability, error) {
	if id == "" {
		return nil, fmt.Errorf("vulnerability ID cannot be empty")
	}

	// Check cache first
	cacheKey := fmt.Sprintf("vuln:id:%s", id)
	if cached, found := getCachedVulnerabilities(cacheKey); found && len(*cached) > 0 {
		return &(*cached)[0], nil
	}

	var vuln model.Vulnerability
	err := db.NewSelect().
		Model(&vuln).
		Where("cve = ?", id).
		Limit(1).
		Scan(context.Background())

	if err != nil {
		// Try searching by other potential ID fields if CVE doesn't work
		err = db.NewSelect().
			Model(&vuln).
			Where("id = ? OR cve = ? OR package LIKE ?", id, id, "%"+id+"%").
			Limit(1).
			Scan(context.Background())
	}

	if err != nil {
		return nil, fmt.Errorf("vulnerability not found: %v", err)
	}

	// Cache the result
	vulnList := []model.Vulnerability{vuln}
	setCachedVulnerabilities(cacheKey, &vulnList)

	return &vuln, nil
}
