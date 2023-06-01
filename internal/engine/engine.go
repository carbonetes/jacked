package engine

import (
	"io"
	"os"
	"time"

	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/internal/analysis"
	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/output"
	diggity "github.com/carbonetes/jacked/internal/sbom"
	"github.com/carbonetes/jacked/internal/ui/credits"
	"github.com/carbonetes/jacked/internal/ui/spinner"
	"github.com/carbonetes/jacked/internal/ui/update"
	"github.com/carbonetes/jacked/pkg/core/model"
)

var log = logger.GetLogger()

// Start the scan engine with the given arguments and configurations
func Start(arguments *model.Arguments, cfg *config.Configuration) {

	var (
		sbom            *dm.SBOM
		licenses        = new([]model.License)
		totalPackages   int
		vulnerabilities []model.Vulnerability
		signatures      = make(map[string]model.Signature)
	)

	start := time.Now()

	// Check database for any updates
	db.DBCheck(*arguments.SkipDbUpdate, *arguments.ForceDbUpdate)
	
	if len(*arguments.SbomFile) > 0 {
		file, err := os.Open(*arguments.SbomFile)
		if err != nil {
			log.Fatalf("\nUnable to Open SBOM JSON file: %v", err)
		}
		result, err := io.ReadAll(file)
		if err != nil {
			log.Fatal(err)
		}
		sbom = diggity.ParseSBOM(&result)
	} else {
		// Request for sbom through event bus
		sbom = diggity.Scan(arguments)
	}
	// Run all parsers and filters for packages

	diggity.Filter(sbom.Packages, &cfg.Ignore.Package)
	if cfg.LicenseFinder {
		diggity.GetLicense(sbom.Packages, licenses)
	}

	totalPackages = len(*sbom.Packages)

	spinner.OnVulnAnalysisStart(totalPackages)

	diggity.Inspect(sbom.Packages, &signatures)

	err := db.Fetch(sbom.Packages, &vulnerabilities, &signatures)
	if err != nil {
		log.Errorf("\nError Fetch Database: %v", err)
	}

	db.Filter(&vulnerabilities,  &cfg.Ignore.Vulnerability)

	// Begin matching vulnerabilities for each package
	analysis.WG.Add(totalPackages)
	for index, pkg := range *sbom.Packages {
		signature := signatures[pkg.ID]
		analysis.FindMatch(&(*sbom.Packages)[index], &vulnerabilities, &signature)
	}
	analysis.WG.Wait()
	spinner.OnStop(nil)

	// Compile the scan results based on the given configurations
	output.PrintResult(sbom, arguments, cfg, licenses)

	log.Printf("\nAnalysis finished in %.2fs", time.Since(start).Seconds())
	err = update.ShowLatestVersion()
	if err != nil {
		log.Errorf("Error on show latest version: %v", err)
	}
	// the argument in show function is to check if it is for testing or not
	credits.Show(false)
}
