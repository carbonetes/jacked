package ci

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/carbonetes/diggity/pkg/convert"
	dm "github.com/carbonetes/diggity/pkg/model"
	diggity "github.com/carbonetes/diggity/pkg/scanner"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/logger"
	jacked "github.com/carbonetes/jacked/pkg/core/analysis"
	"github.com/carbonetes/jacked/pkg/core/ci/assessment"
	"github.com/carbonetes/jacked/pkg/core/ci/table"
	"github.com/carbonetes/jacked/pkg/core/model"
	"github.com/logrusorgru/aurora"
	"golang.org/x/exp/slices"
)

var (
	log                    = logger.GetLogger()
	defaultCriteria string = "LOW"
)

func Analyze(args *model.Arguments) {
	// Check database for any updates
	if !*args.SkipDbUpdate {
		db.DBCheck()
	}
	
	log.Println(aurora.Blue("Entering CI Mode...\n").String())
	if args.FailCriteria == nil || len(*args.FailCriteria) == 0 || !slices.Contains(assessment.Severities, strings.ToUpper(*args.FailCriteria)) {
		log.Warnf("Invalid criteria specified : %v\nSet to default criteria : %v", *args.FailCriteria, defaultCriteria)
		args.FailCriteria = &defaultCriteria
	}
	diggityArgs := dm.NewArguments()
	if len(*args.Image) > 0 {
		log.Printf("Image: %s", *args.Image)
		diggityArgs.Image = args.Image
		diggityArgs.RegistryUsername = args.RegistryUsername
		diggityArgs.RegistryPassword = args.RegistryPassword
		diggityArgs.RegistryURI = args.RegistryURI
		diggityArgs.RegistryToken = args.RegistryToken
	} else if len(*args.Dir) > 0 {
		log.Printf("\tDir: %6s\n", *args.Dir)
		diggityArgs.Dir = args.Dir
	} else if len(*args.Tar) > 0 {
		log.Printf("\tTar: %6s\n", *args.Tar)
		diggityArgs.Tar = args.Tar
	} else {
		log.Fatalf("No valid scan target specified!")
	}
	log.Println(aurora.Blue("\nGenerating CDX BOM...\n"))
	sbom, _ := diggity.Scan(diggityArgs)

	if sbom.Packages == nil {
		log.Error("No package found to analyze!")
	}

	cdx := convert.ToCDX(sbom.Packages)

	table.CDXBomTable(cdx)

	log.Println(aurora.Blue("\nAnalyzing CDX BOM...\n").String())
	jacked.AnalyzeCDX(cdx)

	if len(*cdx.Vulnerabilities) == 0 {
		fmt.Println("No vulnerabilities found!")
	} else {
		table.CDXVexTable(cdx)
	}

	stats := fmt.Sprintf("\nPackages: %9v\nVulnerabilities: %v", len(*cdx.Components), len(*cdx.Vulnerabilities))
	log.Println(aurora.Cyan(stats).String())
	log.Println(aurora.Blue("\nExecuting CI Assessment...\n").String())

	log.Println(aurora.Blue("\nAssessment Result:\n").String())
	if len(*cdx.Vulnerabilities) == 0 {
		log.Println(aurora.Green(aurora.Bold(fmt.Sprintf("\nPassed: %5v found components\n", len(*cdx.Components))).String()))
	}

	result := assessment.Evaluate(args.FailCriteria, cdx)

	table.TallyTable(result.Tally)
	table.MatchTable(result.Matches)
	for _, m := range *result.Matches {
		if len(m.Vulnerability.Recommendation) > 0 {
			log.Warnf("[%v] : %v", m.Vulnerability.ID, m.Vulnerability.Recommendation)
		}
	}
	totalVulnerabilities := len(*cdx.Vulnerabilities)
	if result.Passed {
		log.Println(aurora.Green(aurora.Bold(fmt.Sprintf("\nPassed: %5v out of %v found vulnerabilities passed the assessment\n", totalVulnerabilities, totalVulnerabilities)).String()))
		os.Exit(0)
	}
	log.Error(errors.New(aurora.Red(aurora.Bold(fmt.Sprintf("\nFailed: %5v out of %v found vulnerabilities failed the assessment \n", len(*result.Matches), totalVulnerabilities)).String()).String()))

	os.Exit(1)
}
