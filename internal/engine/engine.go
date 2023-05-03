package engine

import (
	"io"
	"os"
	"time"

	"github.com/carbonetes/jacked/internal/analysis"
	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/events"
	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/output"
	"github.com/carbonetes/jacked/internal/parser"
	"github.com/carbonetes/jacked/internal/ui/credits"
	"github.com/carbonetes/jacked/internal/ui/spinner"
	"github.com/carbonetes/jacked/internal/ui/update"
	"github.com/carbonetes/jacked/pkg/core/model"
)

var (
	vulnerabilities []model.Vulnerability
	results         []model.ScanResult
	packages        []model.Package
	licenses        []model.License
	secrets         model.SecretResults
	totalPackages   int
	log             = logger.GetLogger()
	sbom            []byte
)

// Start the scan engine with the given arguments and configurations
func Start(arguments *model.Arguments, cfg *config.Configuration) {
	start := time.Now()

	// Check database for any updates
	db.DBCheck()
	if len(*arguments.SbomFile) > 0 {
		file, err := os.Open(*arguments.SbomFile)
		if err != nil {
			log.Fatalf("\nUnable to Open SBOM JSON file: %v", err)
		}
		sbom, err = io.ReadAll(file)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// Request for sbom through event bus
		sbom = events.RequestSBOMAnalysis(arguments)
	}

	// Run all parsers and filters for packages
	parser.ParseSBOM(&sbom, &packages, &secrets)
	parser.Filter(&packages, &cfg.Ignore.Package)
	parser.ParsePackages(&packages, &licenses, cfg)

	totalPackages = len(packages)

	spinner.OnVulnAnalysisStart(totalPackages)

	err := db.Fetch(&packages, &vulnerabilities)
	if err != nil {
		log.Errorf("\nError Fetch Database: %v", err)
	}
	db.Filter(&vulnerabilities, &cfg.Ignore.Vulnerability)

	// Begin matching vulnerabilities for each package
	analysis.WG.Add(totalPackages)
	for _, p := range packages {
		var scanresult model.ScanResult
		var result *[]model.Vulnerability = new([]model.Vulnerability)
		analysis.FindMatch(&p, &vulnerabilities, result)
		if *result != nil {
			scanresult.Package = p
			scanresult.Vulnerabilities = *result
			results = append(results, scanresult)
		}
	}
	analysis.WG.Wait()
	spinner.OnVulnAnalysisEnd(nil)

	// Compile the scan results based on the given configurations
	output.PrintResult(&results, arguments, cfg, &secrets, &licenses)

	log.Printf("\nAnalysis finished in %.2fs", time.Since(start).Seconds())
	err = update.ShowLatestVersion()
	if err != nil {
		log.Errorf("Error on show latest version: %v", err)
	}
	credits.Show()
}
