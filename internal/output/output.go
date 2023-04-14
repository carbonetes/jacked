package output

import (
	"fmt"

	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/internal/model"
	"github.com/carbonetes/jacked/internal/output/cyclonedx"
	"github.com/carbonetes/jacked/internal/ui/table"
)

func PrintResult(results *[]model.ScanResult, arguments *model.Arguments, cfg *config.Configuration, secrets *model.SecretResults, licenses *[]model.License) {

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

	if len(*results) == 0 {
		fmt.Print("\nNo vulnerability has been found!")
	}

	if !*arguments.DisableSecretSearch {
		if len(secrets.Secrets) == 0 {
			fmt.Print("\nNo secret has been found!")
		}
	}

	if cfg.LicenseFinder {
		if len(*licenses) == 0 {
			fmt.Print("\nNo license has been found!")
		}
	}

	switch *arguments.Output {
	case "json":
		printJsonResult(results)
		if !*arguments.DisableSecretSearch {
			if len(secrets.Secrets) > 0 {
				printJsonSecret(secrets)
			}
		}
		if cfg.LicenseFinder {
			if len(*licenses) > 0 {
				PrintJsonLicense(licenses)
			}
		}
	case "cyclonedx-json":
		cyclonedx.PrintCycloneDXJSON(results)
		if !*arguments.DisableSecretSearch {
			if len(secrets.Secrets) > 0 {
				printJsonSecret(secrets)
			}
		}
		if cfg.LicenseFinder {
			if len(*licenses) > 0 {
				PrintJsonLicense(licenses)
			}
		}
	case "spdx-json":
		PrintSPDX("json", source, *results)
		if !*arguments.DisableSecretSearch {
			if len(secrets.Secrets) > 0 {
				printJsonSecret(secrets)
			}
		}
		if cfg.LicenseFinder {
			if len(*licenses) > 0 {
				PrintJsonLicense(licenses)
			}
		}
	case "cyclonedx-xml":
		cyclonedx.PrintCycloneDXXML(results)
		if !*arguments.DisableSecretSearch {
			if len(secrets.Secrets) > 0 {
				PrintXMLSecret(secrets)
			}
		}
		if cfg.LicenseFinder {
			if len(*licenses) > 0 {
				PrintXMLLicense(licenses)
			}
		}
	case "spdx-xml":
		PrintSPDX("xml", source, *results)
		if !*arguments.DisableSecretSearch {
			if len(secrets.Secrets) > 0 {
				PrintXMLSecret(secrets)
			}
		}
		if cfg.LicenseFinder {
			if len(*licenses) > 0 {
				PrintXMLLicense(licenses)
			}
		}
	case "spdx-tag-value":
		PrintSPDX("tag-value", source, *results)
	default:
		table.DisplayScanResultTable(results)
		if !*arguments.DisableSecretSearch {
			if len(secrets.Secrets) > 0 {
				table.PrintSecrets(secrets)
			}
		}
		if cfg.LicenseFinder {
			if len(*licenses) > 0 {
				table.PrintLicenses(*licenses)
			}
		}
	}
}
