package engine

import (
	"fmt"
	"io"
	"os"
	"strings"
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
		vulnerabilities = new([]model.Vulnerability)
	)

	start := time.Now()

	// Check database for any updates
	db.DBCheck()
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

	err := db.Fetch(sbom.Packages, vulnerabilities)
	if err != nil {
		log.Errorf("\nError Fetch Database: %v", err)
	}

	db.Filter(vulnerabilities, &cfg.Ignore.Vulnerability)

	// Begin matching vulnerabilities for each package
	analysis.WG.Add(totalPackages)
	for index, _ := range *sbom.Packages {
		go func(sbom *dm.SBOM, vulnerabilities *[]model.Vulnerability, index int) {
			(*sbom.Packages)[index].Vulnerabilities = analysis.FindMatch(&(*sbom.Packages)[index], vulnerabilities)
		}(sbom, vulnerabilities, index)
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
	credits.Show()
}

func failCriteria(pkg *dm.Package, severity *string) {
	vulns := pkg.Vulnerabilities

	Severities := []string{
		"unknown",
		"negligible",
		"low",
		"medium",
		"high",
		"critical",
	}

	index := -1
	for i := 0; i < len(Severities); i++ {
		if Severities[i] == "low" {
			index = i
			break
		}
	}
	var newSeverities []string
	if index != -1 {
		newSeverities = Severities[index:]
	}

	for _, vuln := range *vulns {
		for _, newSeverity := range newSeverities {

			if strings.EqualFold(vuln.CVSS.Severity, newSeverity) {

				log.Errorf("\n\nFAILED: Found a vulnerability that is equal or higher than %v severity!", strings.ToUpper(*severity))
				fmt.Printf("Package Reference: %v | CVE: %v | Severity: %v\n", vuln.Package, vuln.CVE, vuln.CVSS.Severity)
				os.Exit(1)
			}
		}
	}
}
