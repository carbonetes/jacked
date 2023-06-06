package output

import (
	"fmt"
	"strings"

	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/internal/output/cyclonedx"
	"github.com/carbonetes/jacked/internal/output/save"
	"github.com/carbonetes/jacked/internal/ui/table"
	"github.com/carbonetes/jacked/pkg/core/model"
)

func PrintResult(sbom *dm.SBOM, arguments *model.Arguments, cfg *config.Configuration, licenses *[]model.License) {

	if strings.Contains(*arguments.Output, ",") {
		for _, _type := range strings.Split(*arguments.Output, ",") {
			ShowScanResult(_type, sbom, arguments, cfg, licenses)
		}
	} else {
		ShowScanResult(*arguments.Output, sbom, arguments, cfg, licenses)
	}

}

func ShowScanResult(outputType string, sbom *dm.SBOM, arguments *model.Arguments, cfg *config.Configuration, licenses *[]model.License) {
	var source *string
	var outputText string

	if arguments.Image != nil {
		source = arguments.Image
	}
	if arguments.Tar != nil {
		source = arguments.Tar
	}
	if arguments.Dir != nil {
		source = arguments.Dir
	}
	if arguments.SbomFile != nil {
		source = arguments.SbomFile
	}
	switch outputType {
	case "json":
		outputText = printJsonResult(sbom)
		if cfg.LicenseFinder {
			if len(*licenses) > 0 {
				PrintJsonLicense(licenses)
			} else {
				fmt.Print("\nNo license has been found!\n")
			}
		}
		if !*arguments.DisableSecretSearch {
			if len(sbom.Secret.Secrets) > 0 {
				PrintJsonSecret(sbom.Secret)
			} else {
				fmt.Print("\nNo secret has been found!\n")
			}
		}
	case "cyclonedx-json":
		outputText = cyclonedx.PrintCycloneDXJSON(sbom, false)

		if cfg.LicenseFinder {
			if len(*licenses) > 0 {
				PrintJsonLicense(licenses)
			} else {
				fmt.Print("\nNo license has been found!\n")
			}
		}
		if !*arguments.DisableSecretSearch {
			if len(sbom.Secret.Secrets) > 0 {
				PrintJsonSecret(sbom.Secret)
			} else {
				fmt.Print("\nNo secret has been found!\n")
			}
		}
	case "spdx-json":
		outputText = PrintSPDX("json", source, sbom, false)

		if cfg.LicenseFinder {
			if len(*licenses) > 0 {
				PrintJsonLicense(licenses)
			} else {
				fmt.Print("\nNo license has been found!\n")
			}
		}
		if !*arguments.DisableSecretSearch {
			if len(sbom.Secret.Secrets) > 0 {
				PrintJsonSecret(sbom.Secret)
			} else {
				fmt.Print("\nNo secret has been found!\n")
			}
		}
	case "cyclonedx-xml":
		outputText = cyclonedx.PrintCycloneDXXML(sbom, false)

		if cfg.LicenseFinder {
			if len(*licenses) > 0 {
				PrintXMLLicense(licenses)
			} else {
				fmt.Print("\nNo license has been found!\n")
			}
		}
		if !*arguments.DisableSecretSearch {
			if len(sbom.Secret.Secrets) > 0 {
				PrintXMLSecret(sbom.Secret)
			} else {
				fmt.Print("\nNo secret has been found!\n")
			}
		}
	case "spdx-xml":
		outputText = PrintSPDX("xml", source, sbom, false)

		if cfg.LicenseFinder {
			if len(*licenses) > 0 {
				PrintXMLLicense(licenses)
			} else {
				fmt.Print("\nNo license has been found!\n")
			}
		}
		if !*arguments.DisableSecretSearch {
			if len(sbom.Secret.Secrets) > 0 {
				PrintXMLSecret(sbom.Secret)
			} else {
				fmt.Print("\nNo secret has been found!\n")
			}
		}
	case "spdx-tag-value":
		outputText = PrintSPDX("tag-value", source, sbom, false)
	default:
		outputText = table.DisplayScanResultTable(sbom.Packages)
		if cfg.LicenseFinder {
			if len(*licenses) > 0 {
				table.PrintLicenses(*licenses)
			} else {
				fmt.Print("\nNo license has been found!\n")
			}
		}
		if !*arguments.DisableSecretSearch {
			if len(sbom.Secret.Secrets) > 0 {
				table.PrintSecrets(sbom.Secret)
			} else {
				fmt.Print("\nNo secret has been found!\n")
			}
		}
	}

	if arguments.OutputFile != nil && *arguments.OutputFile != "" {
		save.SaveOutputAsFile(*arguments.OutputFile, *arguments.Output, outputText)
	}
}
