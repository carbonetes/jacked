package engine

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/events"
	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/matcher"
	"github.com/carbonetes/jacked/internal/model"
	result "github.com/carbonetes/jacked/internal/output"
	"github.com/carbonetes/jacked/internal/parser"
	"github.com/carbonetes/jacked/internal/ui/credits"
	"github.com/carbonetes/jacked/internal/ui/spinner"
	"github.com/carbonetes/jacked/internal/ui/table"
)

var (
	output          model.Output
	results         []model.ScanResult
	vulnerabilities []model.Vulnerability
	packages        []model.Package
	licenses        []model.License
	secrets         model.SecretResults
	totalPackages   int
	log             = logger.GetLogger()
)

// Start the scan engine with the given arguments and configurations
func Start(arguments *model.Arguments, cfg *config.Configuration) {
	start := time.Now()

	// Check database for any updates
	db.DBCheck()

	// // Request for sbom through event bus
	sbom := events.RequestSBOMAnalysis(arguments)

	// Run all parsers and filters for packages
	parser.ParseSBOM(&sbom, &packages, &secrets)
	parser.Filter(&packages, &cfg.Ignore.Package)
	parser.ParsePackages(&packages, &licenses, cfg)

	totalPackages = len(packages)

	spinner.OnVulnAnalysisStart(totalPackages)

	// Fetch and filter all vulnerabilities for each package
	db.Fetch(&packages, &vulnerabilities)
	db.Filter(&vulnerabilities, &cfg.Ignore.Vulnerability)

	// Begin matching vulnerabilities for each package
	matcher.WG.Add(totalPackages)
	for _, p := range packages {
		var scanresult model.ScanResult
		var result *[]model.Result = new([]model.Result)
		matcher.Matcher(&p, result, &vulnerabilities)
		if *result != nil {
			scanresult.Package = p
			scanresult.Vulnerabilities = *result
			results = append(results, scanresult)
		}
	}
	matcher.WG.Wait()
	spinner.OnVulnAnalysisEnd(nil)

	// Compile the scan results based on the given configurations
	switch cfg.Output {
	case "json":
		if cfg.LicenseFinder && len(licenses) > 0 {
			output.Licenses = licenses
		} else {
			log.Print("\nNo package license has been found!")
		}
		if !cfg.SecretConfig.Disabled && len(secrets.Secrets) > 0 {
			output.Secrets = &secrets
		} else {
			log.Print("\nNo secret has been found!")
		}
		if len(results) > 0 {
			output.Results = results
		} else {
			log.Print("\nNo vulnerability found!")
		}
		fmt.Printf("%v", printJSONResult())
	case "cyclonedx-xml":
		result.PrintCycloneDX("xml", results)
	case "cyclonedx-json":
		result.PrintCycloneDX("json", results)
	case "spdx-json":
		result.PrintSPDX("json", arguments.Image, results)
	case "spdx-xml":
		result.PrintSPDX("xml", arguments.Image, results)
	case "spdx-tag-value":
		result.PrintSPDX("tag-value", arguments.Image, results)
	default:
		log.Println()
		if len(results) > 0 {
			table.DisplayScanResultTable(results)
		} else {
			log.Print("\nNo vulnerability found!")
		}

		if cfg.LicenseFinder {
			if len(licenses) > 0 {
				table.PrintLicenses(licenses)
			} else {
				log.Print("\nNo package license has been found!")
			}
		}

		if !cfg.SecretConfig.Disabled {
			if len(secrets.Secrets) > 0 {
				table.PrintSecrets(secrets)
			} else {
				log.Print("\nNo secret has been found!")
			}
		}
	}

	log.Printf("\nAnalysis finished in %.2fs", time.Since(start).Seconds())
	credits.Show()
}

// Print json format of the scan results
func printJSONResult() string {
	jsonraw, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		log.Printf("Error marshalling: %v", err.Error())
	}

	return string(jsonraw)
}
