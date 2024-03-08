package analyzer

import (
	"fmt"
	"time"

	"github.com/carbonetes/diggity/pkg/cdx"
	"github.com/carbonetes/diggity/pkg/reader"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/internal/presenter"
	"github.com/carbonetes/jacked/internal/tea/spinner"
	"github.com/carbonetes/jacked/pkg/types"
)

// New is the main function for the analyzer
// It checks if the database is up to date, then scans the target with diggity
// It then gets the sbom from cdx mod and analyzes it to find vulnerabilities
// Finally, it displays the results
func New(params types.Parameters) {

	// Check if the database is up to date
	db.DBCheck(params.SkipDBUpdate, params.ForceDBUpdate)

	start := time.Now()

	switch params.Diggity.ScanType {
	case 1: // Image
		spinner.Set(fmt.Sprintf("Fetching %s from remote registry", params.Diggity.Input))
		// Scan target with diggity
		diggityParams := params.Diggity

		// Pull and read image from registry
		image, err := reader.GetImage(diggityParams.Input, nil)
		if err != nil {
			log.Fatal(err)
		}

		err = reader.ReadFiles(image)
		if err != nil {
			log.Fatal(err)
		}
	case 2: // Tarball
		spinner.Set(fmt.Sprintf("Reading %s", params.Diggity.Input))
		image, err := reader.ReadTarballAsImage(params.Diggity.Input)
		if err != nil {
			log.Error(err)
		}
		err = reader.ReadFiles(image)
		if err != nil {
			log.Error(err)
		}
	case 3: // Filesystem
		reader.FilesystemScanHandler(params.Diggity.Input)
	default:
		log.Fatal("Invalid scan type")
	}

	// Get sbom from cdx mod
	sbom := cdx.BOM

	// Analyze sbom to find vulnerabilities
	AnalyzeCDX(sbom)

	elapsed := time.Since(start).Seconds()

	spinner.Done()

	// Display the results
	presenter.Display(params, elapsed)
}