package output

import (
	"fmt"
	"strings"

	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/internal/output/cyclonedx"
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
		printJsonResult(sbom)
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
		cyclonedx.PrintCycloneDXJSON(sbom)

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
		PrintSPDX("json", source, sbom)

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
		cyclonedx.PrintCycloneDXXML(sbom)

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
		PrintSPDX("xml", source, sbom)

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
		PrintSPDX("tag-value", source, sbom)
	default:
		table.DisplayScanResultTable(sbom.Packages)
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
}
