package analyzer

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/compare"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/scan"
	"github.com/carbonetes/jacked/pkg/scan/generic"
	"github.com/carbonetes/jacked/pkg/scan/golang"
	"github.com/carbonetes/jacked/pkg/scan/maven"
	"github.com/carbonetes/jacked/pkg/scan/npm"
	"github.com/carbonetes/jacked/pkg/scan/os/apk"
	"github.com/carbonetes/jacked/pkg/scan/os/dpkg"
	"github.com/carbonetes/jacked/pkg/scan/os/rpm"
)

// AnalyzeCDX is a function that takes a CycloneDX BOM as input and analyzes it for vulnerabilities.
func AnalyzeCDX(sbom *cyclonedx.BOM) {
	// If the BOM is nil, return immediately.
	if sbom == nil {
		return
	}

	// If there are no components in the BOM, return immediately.
	if len(*sbom.Components) == 0 {
		return
	}

	// Call in the compare package to execute the comparison of the BOM.
	// The comparison will search for vulnerabilities affecting the components in the BOM and append any found vulnerabilities to the BOM's Vulnerabilities list.
	compare.Analyze(sbom)
}

func Analyze(bom *cyclonedx.BOM) {
	if bom == nil {
		return
	}

	if bom.Components == nil {
		return
	}

	if len(*bom.Components) == 0 {
		return
	}

	// Run all scanners collectively
	scanManager := scan.NewManager(
		dpkg.NewScanner(db.Store{}),
		apk.NewScanner(db.Store{}),
		maven.NewScanner(db.Store{}),
		golang.NewScanner(db.Store{}),
		rpm.NewScanner(db.Store{}),
		npm.NewScanner(db.Store{}),
		generic.NewScanner(db.Store{}),
	)
	vulns, err := scanManager.Run(bom)
	if err != nil {
		// Handle error as needed (log, return, etc.)
		log.Debugf("error during scan: %v", err)
		return
	}

	bom.Vulnerabilities = &vulns
}
