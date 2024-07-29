package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/carbonetes/diggity/pkg/cdx"
	"github.com/carbonetes/diggity/pkg/reader"
	diggity "github.com/carbonetes/diggity/pkg/types"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/internal/presenter"
	"github.com/carbonetes/jacked/internal/tea/spinner"
	"github.com/carbonetes/jacked/pkg/analyzer"
	"github.com/carbonetes/jacked/pkg/ci"
	"github.com/carbonetes/jacked/pkg/config"
	"github.com/carbonetes/jacked/pkg/types"
)

// New is the main function for the analyzer
// It checks if the database is up to date, then scans the target with diggity
// It then gets the sbom from cdx mod and analyzes it to find vulnerabilities
// Finally, it displays the results
func Run(params types.Parameters) {

	// Check if the database is up to date
	db.DBCheck(params.SkipDBUpdate, params.ForceDBUpdate)
	db.Load()
	start := time.Now()

	diggityParams := params.Diggity
	// Generate unique address for the scan
	addr, err := diggity.NewAddress()
	if err != nil {
		log.Debug(err)
		return
	}

	cdx.New(addr)
	switch params.Diggity.ScanType {
	case 1: // Image
		spinner.Set(fmt.Sprintf("Fetching %s from remote registry", params.Diggity.Input))
		// Scan target with diggity

		// Pull and read image from registry
		image, ref, err := reader.GetImage(diggityParams.Input, nil)
		if err != nil {
			log.Fatal(err)
		}

		cdx.SetMetadataComponent(addr, cdx.SetImageMetadata(*image, *ref, diggityParams.Input))

		err = reader.ReadFiles(image, addr)
		if err != nil {
			log.Fatal(err)
		}
	case 2: // Tarball
		spinner.Set(fmt.Sprintf("Reading tarfile %s", params.Diggity.Input))
		image, err := reader.ReadTarballAsImage(params.Diggity.Input)
		if err != nil {
			log.Fatal(err)
		}
		err = reader.ReadFiles(image, addr)
		if err != nil {
			log.Fatal(err)
		}
	case 3: // Filesystem
		spinner.Set(fmt.Sprintf("Reading directory %s", params.Diggity.Input))
		err := reader.FilesystemScanHandler(diggityParams.Input, addr)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("Invalid scan type")
	}

	bom := cdx.Finalize(addr)
	// Analyze sbom to find vulnerabilities
	analyzer.AnalyzeCDX(bom)

	if params.CI {
		// Run CI
		ci.Run(config.Config.CI, bom)
		os.Exit(0)
	}

	elapsed := time.Since(start).Seconds()

	spinner.Done()

	// Display the results
	presenter.Display(params, elapsed, bom)
}
