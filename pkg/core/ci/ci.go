package ci

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/carbonetes/diggity/pkg/convert"
	dm "github.com/carbonetes/diggity/pkg/model"
	diggity "github.com/carbonetes/diggity/pkg/scanner"
	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/db"
	bomUtil "github.com/carbonetes/jacked/internal/sbom"
	save "github.com/carbonetes/jacked/internal/output/save"
	jacked "github.com/carbonetes/jacked/pkg/core/analysis"
	"github.com/carbonetes/jacked/pkg/core/ci/assessment"
	filter "github.com/carbonetes/jacked/pkg/core/ci/filter"
	"github.com/carbonetes/jacked/pkg/core/ci/table"
	"github.com/carbonetes/jacked/pkg/core/model"
	"golang.org/x/exp/slices"
)

var (
	log                    = logger.GetLogger()
	defaultCriteria string = "LOW"
)

func Analyze(args *model.Arguments, ciCfg *config.CIConfiguration) {
	var outputText string
	// Check database for any updates
    db.DBCheck(*args.SkipDbUpdate)

	log.Println("Entering CI Mode...")
	if args.FailCriteria == nil || len(*args.FailCriteria) == 0 || !slices.Contains(assessment.Severities, strings.ToUpper(*args.FailCriteria)) {
		warningMessage := fmt.Sprintf("\nInvalid criteria specified : %v\nSet to default criteria : %v", *args.FailCriteria, defaultCriteria)
		log.Warnf(warningMessage)
		outputText = warningMessage
		args.FailCriteria = &defaultCriteria
	}
	diggityArgs := dm.NewArguments()
	if len(*args.Image) > 0 {
		imageInfo := fmt.Sprintf("\nImage: %s", *args.Image)
		log.Printf(imageInfo)
		outputText += imageInfo + "\n\n"
		diggityArgs.Image = args.Image
		diggityArgs.RegistryUsername = args.RegistryUsername
		diggityArgs.RegistryPassword = args.RegistryPassword
		diggityArgs.RegistryURI = args.RegistryURI
		diggityArgs.RegistryToken = args.RegistryToken
	} else if len(*args.Dir) > 0 {
		dirInfo := fmt.Sprintf("\tDir: %6s\n", *args.Dir)
		log.Printf(dirInfo)
		outputText += dirInfo + "\n\n"
		diggityArgs.Dir = args.Dir
	} else if len(*args.Tar) > 0 {
		tarInfo := fmt.Sprintf("\tTar: %6s\n", *args.Tar)
		log.Printf(tarInfo)
		outputText += tarInfo + "\n\n"
		diggityArgs.Tar = args.Tar
	} else {
		log.Fatalf("No valid scan target specified!")
	}
	log.Println("\nGenerating CDX BOM...\n")
	sbom, _ := diggity.Scan(diggityArgs)

	bomUtil.Filter(sbom.Packages, &ciCfg.FailCriteria.Package)

	if sbom.Packages == nil {
		log.Error("No package found to analyze!")
	}

	cdx := convert.ToCDX(sbom.Packages)

	outputText += "Generated CDX BOM\n\n" + table.CDXBomTable(cdx)

	log.Println("\nAnalyzing CDX BOM...\n")
	jacked.AnalyzeCDX(cdx)
	
	filter.IgnoreVuln(cdx.Vulnerabilities, &ciCfg.FailCriteria.Vulnerability)
	if len(*cdx.Vulnerabilities) == 0 {
		fmt.Println("No vulnerabilities found!")
		outputText += "\nNo vulnerabilities found! \n"
	} else {
		outputText += "\n\nAnalyzed CDX BOM \n\n" + table.CDXVexTable(cdx)
	}

	stats := fmt.Sprintf("\nPackages: %9v\nVulnerabilities: %v", len(*cdx.Components), len(*cdx.Vulnerabilities))
	outputText += "\n" + stats
	log.Println(stats)

	log.Println("\nShowing Ignore List...\n")
	outputText += "\n\nIgnore List\n"
	outputText += "\n" + table.IgnoreListTable(&ciCfg.FailCriteria)

	log.Println("\nExecuting CI Assessment...")

	log.Println("\nAssessment Result:\n")
	outputText += "\n\nAssessment Result:\n"
	if len(*cdx.Vulnerabilities) == 0 {
		message := fmt.Sprintf("\nPassed: %5v found components\n", len(*cdx.Components))
		outputText += message
		log.Println(message)
	}

	result := assessment.Evaluate(args.FailCriteria, cdx)

	outputText += "\n"+table.TallyTable(result.Tally)
	outputText += "\n"+table.MatchTable(result.Matches)
	for _, m := range *result.Matches {
		if len(m.Vulnerability.Recommendation) > 0 {
			recMessage := fmt.Sprintf("[%v] : %v", m.Vulnerability.ID, m.Vulnerability.Recommendation)
			outputText += "\n" + recMessage
			log.Warnf(recMessage)
		}
	}
	totalVulnerabilities := len(*cdx.Vulnerabilities)
	if result.Passed {
		passedMessage := fmt.Sprintf("\nPassed: %5v out of %v found vulnerabilities passed the assessment\n", totalVulnerabilities, totalVulnerabilities)
		outputText += "\n" + passedMessage
		log.Println(passedMessage)
		saveOutputFile(args,outputText)
		os.Exit(0)
	}
	failedMessage := fmt.Sprintf("\nFailed: %5v out of %v found vulnerabilities failed the assessment \n", len(*result.Matches), totalVulnerabilities)
	outputText += "\n" + failedMessage
	log.Error(errors.New(failedMessage))
	saveOutputFile(args,outputText)
	os.Exit(1)
}

func saveOutputFile(args *model.Arguments, outputText string){
	if args.OutputFile != nil && *args.OutputFile != ""{
		// we can use the *args.Output for the second args on the parameter, for now it only supports table/txt output
		save.SaveOutputAsFile(*args.OutputFile,"table", outputText )
	}
}