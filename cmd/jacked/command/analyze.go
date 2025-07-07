package command

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/diggity/pkg/cdx"
	"github.com/carbonetes/diggity/pkg/reader"
	diggity "github.com/carbonetes/diggity/pkg/types"
	"github.com/carbonetes/jacked/cmd/jacked/ui/spinner"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/analyzer"
	"github.com/carbonetes/jacked/pkg/ci"
	"github.com/carbonetes/jacked/pkg/config"
	"github.com/carbonetes/jacked/pkg/scan"
	"github.com/golistic/urn"
)

// analyze is the main analyzer function
func analyze(params scan.Parameters) {
	runSimpleAnalysis(params)
}

// runSimpleAnalysis provides a simple, direct analysis path - replaces cli.Run
func runSimpleAnalysis(params scan.Parameters) {
	// Check if the database is up to date
	db.DBCheck(params.SkipDBUpdate, params.ForceDBUpdate)
	db.Load()
	start := time.Now()

	// Set spinner mode based on parameters
	spinner.Skip = params.Quiet || params.NonInteractive

	// Generate BOM
	bom := generateBOMFromParams(params)
	if bom == nil {
		log.Error("Failed to generate BOM")
		return
	}

	if !spinner.Skip {
		spinner.Set("Analyzing SBOM for vulnerabilities")
	}

	// Analyze BOM for vulnerabilities
	analyzer.AnalyzeCDX(bom)

	if !spinner.Skip {
		spinner.Done()
	}

	// Handle CI mode
	if params.CI {
		ci.Run(config.Config.CI, bom)
		os.Exit(0)
	}

	elapsed := time.Since(start).Seconds()
	log.Debug("SBOM analysis complete")

	// Display results with basic output
	if !params.Quiet {
		displayBasicResults(params, elapsed, bom)
	}
}

// generateBOMFromParams generates BOM using existing diggity parameters
func generateBOMFromParams(params scan.Parameters) *cyclonedx.BOM {
	// Use the existing diggity integration to generate the BOM
	log.Debug("Generating BOM using diggity...")

	// Generate unique address for the scan
	addr, err := diggity.NewAddress()
	if err != nil {
		log.Debugf("Error creating diggity address: %v", err)
		return nil
	}

	cdx.New(addr)

	switch params.Diggity.ScanType {
	case 1: // Image
		return generateBOMFromImage(params, addr)
	case 2: // Tarball
		return generateBOMFromTarball(params, addr)
	case 3: // Filesystem
		return generateBOMFromFilesystem(params, addr)
	default:
		log.Debug("Invalid scan type")
		return nil
	}
}

// generateBOMFromImage handles image-based BOM generation
func generateBOMFromImage(params scan.Parameters, addr *urn.URN) *cyclonedx.BOM {
	diggityParams := params.Diggity

	if !spinner.Skip {
		spinner.Set("Reading image from registry: " + diggityParams.Input)
	}

	// Pull and read image from registry
	image, ref, err := reader.GetImage(diggityParams.Input, nil)
	if err != nil {
		log.Debugf("Error getting image: %v", err)
		return nil
	}

	cdx.SetMetadataComponent(addr, cdx.SetImageMetadata(*image, *ref, diggityParams.Input))

	err = reader.ReadFiles(image, addr)
	if err != nil {
		log.Debugf("Error reading image files: %v", err)
		return nil
	}

	return cdx.Finalize(addr)
}

// generateBOMFromTarball handles tarball-based BOM generation
func generateBOMFromTarball(params scan.Parameters, addr *urn.URN) *cyclonedx.BOM {
	if !params.Quiet {
		log.Infof("Reading tarfile %s", params.Diggity.Input)
	}
	image, err := reader.ReadTarball(params.Diggity.Input)
	if err != nil {
		log.Debugf("Error reading tarball: %v", err)
		return nil
	}
	err = reader.ReadFiles(image, addr)
	if err != nil {
		log.Debugf("Error reading tarball files: %v", err)
		return nil
	}

	return cdx.Finalize(addr)
}

// generateBOMFromFilesystem handles filesystem-based BOM generation
func generateBOMFromFilesystem(params scan.Parameters, addr *urn.URN) *cyclonedx.BOM {
	if !params.Quiet {
		log.Infof("Reading directory %s", params.Diggity.Input)
	}
	err := reader.FilesystemScanHandler(params.Diggity.Input, addr)
	if err != nil {
		log.Debugf("Error scanning filesystem: %v", err)
		return nil
	}

	return cdx.Finalize(addr)
}

// displayBasicResults provides enhanced console output for scan results
func displayBasicResults(params scan.Parameters, elapsed float64, bom *cyclonedx.BOM) {
	if bom == nil {
		fmt.Println("No results to display")
		return
	}

	vulnCount := 0
	if bom.Vulnerabilities != nil {
		vulnCount = len(*bom.Vulnerabilities)
	}

	componentCount := 0
	if bom.Components != nil {
		componentCount = len(*bom.Components)
	}

	// Handle file output first
	if len(params.File) > 0 {
		err := saveResultsToFile(bom, params.File, params.Format)
		if err != nil {
			log.Debugf("Failed to save results to file: %s", err.Error())
		}
		fmt.Printf("Results saved to: %s\n", params.File)
		return
	}

	// Handle different output formats
	switch params.Format {
	case scan.Table:
		// Always use non-interactive table output - just display and exit
		displayTableResultsNonInteractive(bom, elapsed)
	case scan.JSON:
		result, err := helper.ToJSON(*bom)
		if err != nil {
			log.Debug(err)
		}
		fmt.Print(string(result))
	default:
		// Default to summary display
		displayScanSummary(componentCount, vulnCount, elapsed)
	}
}

// displayScanSummary shows a text summary of scan results
func displayScanSummary(componentCount, vulnCount int, elapsed float64) {
	fmt.Printf("\nScan Results:\n")
	fmt.Printf("  Components scanned: %d\n", componentCount)
	fmt.Printf("  Vulnerabilities found: %d\n", vulnCount)
	fmt.Printf("  Scan duration: %.2f seconds\n", elapsed)

	if vulnCount > 0 {
		fmt.Printf("\nFound %d vulnerabilities in the scanned components.\n", vulnCount)
		fmt.Printf("Use table format for detailed vulnerability information.\n")
	} else {
		fmt.Printf("\nNo vulnerabilities found.\n")
	}
}

// saveResultsToFile saves scan results to a file in the specified format
func saveResultsToFile(bom *cyclonedx.BOM, filePath string, format scan.Format) error {
	return helper.SaveToFile(bom, filePath, format.String())
}

// displayTableResultsNonInteractive displays vulnerability results in a simple table format without Bubble Tea
func displayTableResultsNonInteractive(bom *cyclonedx.BOM, elapsed float64) {
	if bom == nil || bom.Vulnerabilities == nil {
		fmt.Printf("No vulnerabilities found\nScan duration: %.3f seconds\n", elapsed)
		return
	}

	vulnerabilities := *bom.Vulnerabilities
	if len(vulnerabilities) == 0 {
		fmt.Printf("No vulnerabilities found\nScan duration: %.3f seconds\n", elapsed)
		return
	}

	components := buildComponentMap(bom.Components)
	printTableHeader(len(vulnerabilities))
	printVulnerabilityRows(vulnerabilities, components)
	fmt.Printf("\nScan duration: %.3f seconds\n", elapsed)
}

// buildComponentMap creates a lookup map for components
func buildComponentMap(components *[]cyclonedx.Component) map[string]string {
	componentMap := make(map[string]string)
	if components != nil {
		for _, c := range *components {
			componentMap[c.BOMRef] = c.Name + ":" + c.Version
		}
	}
	return componentMap
}

// printTableHeader prints the table header
func printTableHeader(vulnCount int) {
	fmt.Printf("Vulnerability Report (%d found)\n", vulnCount)
	fmt.Printf("%-28s %-18s %-18s %-20s %-40s\n", "Component", "Version", "CVE ID", "Severity", "Fix Available")
	fmt.Printf("%s\n", strings.Repeat("-", 124))
}

// printVulnerabilityRows prints all vulnerability rows
func printVulnerabilityRows(vulnerabilities []cyclonedx.Vulnerability, components map[string]string) {
	for _, v := range vulnerabilities {
		component, ok := components[v.BOMRef]
		if !ok {
			continue
		}

		name, version := parseComponentInfo(component)
		severity := extractSeverity(v)
		recommendation := getVulnRecommendation(v)

		// Truncate long strings to fit in columns
		name = truncateString(name, 26)
		version = truncateString(version, 16)
		recommendation = truncateString(recommendation, 38)

		fmt.Printf("%-28s %-18s %-18s %-20s %-40s\n", name, version, v.ID, severity, recommendation)
	}
}

// parseComponentInfo splits component string into name and version
func parseComponentInfo(component string) (string, string) {
	parts := strings.Split(component, ":")
	name := parts[0]
	var version string
	if len(parts) > 1 {
		version = strings.Join(parts[1:], ":")
	}
	return name, version
}

// extractSeverity gets severity from vulnerability ratings
func extractSeverity(v cyclonedx.Vulnerability) string {
	if v.Ratings != nil && len(*v.Ratings) > 0 {
		for _, r := range *v.Ratings {
			if r.Severity != "" {
				return strings.ToUpper(string(r.Severity))
			}
		}
	}
	return "UNKNOWN"
}

// getVulnRecommendation gets recommendation or default value
func getVulnRecommendation(v cyclonedx.Vulnerability) string {
	if v.Recommendation != "" {
		return v.Recommendation
	}
	return "Update to latest version"
}

// truncateString truncates a string if it exceeds maxLength
func truncateString(s string, maxLength int) string {
	if len(s) > maxLength {
		return s[:maxLength-3] + "..."
	}
	return s
}
