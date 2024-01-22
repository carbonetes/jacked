package output

import (
	"strings"

	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/output/cyclonedx"
	"github.com/carbonetes/jacked/internal/output/save"
	"github.com/carbonetes/jacked/internal/ui/table"
	"github.com/carbonetes/jacked/pkg/core/model"
)

const (
	noLicenseFound = "\nNo license has been found!"
	noSecretsFound = "\nNo secret has been found!"
)

var log = logger.GetLogger()

// Output functions for each type
var outputFuncs = map[string]func(*dm.SBOM) string{
	"table":    table.DisplayScanResultTable,
	"json":     printJsonResult,
	"cdx-json": cyclonedx.PrintCycloneDXJSON,
	"cdx-xml":  cyclonedx.PrintCycloneDX,
}

// PrintResult prints the scan result based on the specified output types.
func PrintResult(sbom *dm.SBOM, arguments *model.Arguments, cfg *config.Configuration, licenses *[]model.License) {
	outputTypes := strings.Split(*arguments.Output, ",")

	for _, outputType := range outputTypes {
		outputText := generateOutput(outputType, sbom, arguments, cfg, licenses)

		if arguments.OutputFile != nil && *arguments.OutputFile != "" {
			if err := save.SaveOutputAsFile(*arguments.OutputFile, *arguments.Output, outputText); err != nil {
				log.Printf("Error saving output to file: %v\n", err)
			}
		}

		if !*arguments.Quiet {
			log.Printf("\n%s", outputText)
		}
	}
}

// generateOutput generates output text based on the specified output type.
func generateOutput(outputType string, sbom *dm.SBOM, arguments *model.Arguments, cfg *config.Configuration, licenses *[]model.License) string {
	outputFunc, exists := outputFuncs[outputType]
	if !exists {
		// Use the default output function for unknown types
		outputFunc = outputFuncs["default"]
	}

	outputText := outputFunc(sbom)

	if cfg.LicenseFinder {
		if len(*licenses) > 0 {
			printLicense(licenses, outputType)
		} else {
			outputText += noLicenseFound
		}
	}

	if !*arguments.DisableSecretSearch {
		if len(sbom.Secret.Secrets) > 0 {
			printSecret(sbom.Secret, outputType)
		} else {
			outputText += noSecretsFound
		}
	}

	return outputText
}

// printLicense prints license information based on the output type.
func printLicense(licenses *[]model.License, outputType string) {
	switch outputType {
	case "json", "cdx-json", "cdx-xml":
		PrintJsonLicense(licenses)
	default:
		table.PrintLicenses(*licenses)
	}
}

// printSecret prints secret information based on the output type.
func printSecret(secret *dm.SecretResults, outputType string) {
	switch outputType {
	case "json", "cdx-json", "cdx-xml":
		PrintJsonSecret(secret)
	default:
		table.PrintSecrets(secret)
	}
}
