package ci

import (
	"errors"
	"fmt"
	"os"

	"github.com/carbonetes/diggity/pkg/convert"
	dm "github.com/carbonetes/diggity/pkg/model"
	diggity "github.com/carbonetes/diggity/pkg/scanner"
	"github.com/carbonetes/jacked/internal/logger"
	jacked "github.com/carbonetes/jacked/pkg/core/analysis"
	"github.com/carbonetes/jacked/pkg/core/ci/assessment"
	"github.com/carbonetes/jacked/pkg/core/ci/table"
	"github.com/carbonetes/jacked/pkg/core/model"
	"github.com/logrusorgru/aurora"
)

var log = logger.GetLogger()

func Analyze(args *model.Arguments) {
	log.Println(aurora.Blue("Entering CI Mode...\n").String())

	diggityArgs := dm.NewArguments()
	if len(*args.Image) > 0 {
		log.Printf("\tImage: %6s", *args.Image)
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
	sbom := diggity.Scan(diggityArgs)

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
	if len(*cdx.Vulnerabilities) > 0 {
		tally := assessment.CheckTally(cdx.Vulnerabilities)
		table.TallyTable(tally)
		log.Error(errors.New(aurora.Red(aurora.Bold(fmt.Sprintf("\nFailed: %5v found vulnerabilities\n", len(*cdx.Vulnerabilities))).String()).String()))
		for _, v := range *cdx.Vulnerabilities {
			if len(v.Recommendation) > 0 {
				log.Warning(aurora.Yellow(fmt.Sprintf("[%v]: ", v.ID)).String(), aurora.Yellow(fmt.Sprintf("%4s", v.Recommendation)).String())
			}
		}
	} else {
		log.Println(aurora.Green(aurora.Bold(fmt.Sprintf("\nPassed: %5v found components\n", len(*cdx.Components))).String()))
	}
	os.Exit(0)
}
