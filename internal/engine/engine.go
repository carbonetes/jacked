package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
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
	"github.com/carbonetes/jacked/internal/ui/update"
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
	sbom            []byte
	file            *string
	severity        *string
)

// Start the scan engine with the given arguments and configurations
func Start(arguments *model.Arguments, cfg *config.Configuration) {
	start := time.Now()

	// Check database for any updates
	db.DBCheck()
	if len(*arguments.SbomFile) > 0 {
		file, err := os.Open(*arguments.SbomFile)
		if err != nil {
			log.Fatalln(err.Error())
		}
		sbom, err = io.ReadAll(file)
		if err != nil {
			log.Fatalln(err.Error())
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

			if len(*arguments.FailCriteria) > 0 {
				severity = arguments.FailCriteria
				failCriteria(scanresult, severity)
			}

		}
	}
	matcher.WG.Wait()
	spinner.OnVulnAnalysisEnd(nil)

	// Get scan type value
	if arguments.Image != nil {
		file = arguments.Image
	}
	if arguments.Tar != nil {
		file = arguments.Tar
	}
	if arguments.Dir != nil {
		file = arguments.Dir
	}
	if arguments.SbomFile != nil {
		file = arguments.SbomFile
	}

	// Compile the scan results based on the given configurations
	selectOutputType(*arguments.Output, cfg, arguments)

	log.Printf("\nAnalysis finished in %.2fs", time.Since(start).Seconds())
	err := update.ShowLatestVersion()
	if err != nil {
		log.Printf("Error on show latest version: %v", err)
	}
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

// Select Output Type based on the User Input
func selectOutputType(outputTypes string, cfg *config.Configuration, arguments *model.Arguments) {
	for _, userOutput := range strings.Split(outputTypes, ",") {
		switch userOutput {
		case "json":
			if cfg.LicenseFinder && len(licenses) > 0 {
				output.Licenses = licenses
			} else if cfg.LicenseFinder && len(licenses) == 0 {
				log.Print("\nNo package license has been found!")
			}
			if !cfg.SecretConfig.Disabled && len(secrets.Secrets) > 0 {
				output.Secrets = &secrets
			} else if !cfg.SecretConfig.Disabled && len(secrets.Secrets) == 0 {
				log.Print("\nNo secret has been found!")
			}
			if len(results) > 0 {
				output.Results = results
			} else {
				log.Print("\nNo vulnerability found!")
			}
			fmt.Printf("%v", printJSONResult())
		// CycloneDX Output Types
		case "cyclonedx-xml":
			result.PrintCycloneDX("xml", results)
		case "cyclonedx-json":
			result.PrintCycloneDX("json", results)
		case "cyclonedx-vex-xml":
			result.PrintCycloneDX("vex-xml", results)
		case "cyclonedx-vex-json":
			result.PrintCycloneDX("vex-json", results)
		// SPDX Output Types
		case "spdx-json":
			result.PrintSPDX("json", file, results)
		case "spdx-xml":
			result.PrintSPDX("xml", file, results)
		case "spdx-tag-value":
			result.PrintSPDX("tag-value", file, results)
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
		log.Println()

	}
}

func failCriteria(scanresult model.ScanResult, severity *string) {
	vulns := scanresult.Vulnerabilities

	for _, vuln := range vulns {
		if strings.EqualFold(vuln.CVSS.Severity, *severity) {

			log.Printf("Package: %v | CVE: %v | Severity: %v", vuln.Package, vuln.CVE, vuln.CVSS.Severity)
			log.Errorf("%v found on scan result:", *severity)
			os.Exit(1)
		}
	}
}
