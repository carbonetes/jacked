package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"time"

	"github.com/carbonetes/jacked/internal/model"
	spdxutils "github.com/carbonetes/jacked/internal/output/spdx-utils"
)

var arguments model.Arguments

func PrintSPDX(formatType string, image *string, results []model.ScanResult) {

	spdx := GetSpdx(image, results)

	switch formatType {
	case "xml":
		result, _ := xml.MarshalIndent(spdx, "", " ")
		fmt.Printf("%+v\n", string(result))
	case "json":
		result, _ := json.MarshalIndent(spdx, "", " ")
		fmt.Printf("%+v\n", string(result))
	default:
		fmt.Printf("Format type not found")
	}
}

func GetSpdx(image *string, results []model.ScanResult) model.SpdxDocument {

	formatName := spdxutils.FormatName(image)

	result := model.SpdxDocument{
		SPDXID:      spdxutils.Ref,
		Name:        formatName,
		SpdxVersion: spdxutils.Version,
		CreationInfo: model.CreationInfo{
			Created:            time.Now().UTC(),
			Creators:           spdxutils.CreateInfo,
			LicenseListVersion: spdxutils.LicenseListVersion,
		},
		DataLicense:       spdxutils.DataLicense,
		DocumentNamespace: spdxutils.FormatNamespace(formatName),
		SpdxPackages:      spdxPackages(results),
	}
	return result
}

// spdxJSONPackages Get Packages in SPDX-JSON format
func spdxPackages(results []model.ScanResult) (spdxPkgs []model.SpdxPackage) {

	for _, result := range results {
		spdxPkgs = append(spdxPkgs, model.SpdxPackage{
			SpdxID:           spdxutils.Ref + result.Package.ID,
			Name:             result.Package.Name,
			Description:      result.Package.Description,
			DownloadLocation: spdxutils.DownloadLocation(&result.Package),
			LicenseConcluded: spdxutils.LicensesDeclared(&result.Package),
			ExternalRefs:     spdxutils.ExternalRefs(&result.Package),
			FilesAnalyzed:    false, // If false, indicates packages that represent metadata or URI references to a project, product, artifact, distribution or a component.
			Homepage:         spdxutils.Homepage(&result.Package),
			LicenseDeclared:  spdxutils.LicensesDeclared(&result.Package),
			Originator:       spdxutils.Originator(&result.Package),
			SourceInfo:       spdxutils.SourceInfo(&result.Package),
			VersionInfo:      result.Package.Version,
			Copyright:        spdxutils.NoAssertion,
			Vulnerabilities:  result.Vulnerabilities,
		})
	}
	return spdxPkgs
}

// GetSpdxTagValues Parse SPDX-TAG_VALUE format
func GetSpdxTagValues() (spdxTagValues []string) {
	spdxTagValues = append(spdxTagValues, fmt.Sprintf(
		"SPDXVersion: %s\n"+
			"DataLicense: %s\n"+
			"SPDXID: %s\n"+
			"DocumentName: %s\n"+
			"DocumentNamespace: %s\n"+
			"LicenseListVersion: %s\n"+
			"Creator: %s\n"+
			"Creator: %s\n"+
			"Created: %+v",
		spdxutils.Version,                     // SPDXVersion
		spdxutils.DataLicense,                 // DataLicense
		spdxutils.Ref+spdxutils.Doc,           // SPDXID
		spdxutils.FormatName(arguments.Image), // DocumentName
		spdxutils.FormatNamespace(spdxutils.FormatName(arguments.Image)), // DocumentNamespace
		spdxutils.LicenseListVersion,                                     // LicenseListVersion
		spdxutils.Creator,                                                // Creator: Organization
		spdxutils.Tool,                                                   // Creator: Tool
		time.Now().UTC().Format(time.RFC3339),                            // Created
	))
	var results []model.ScanResult
	// Parse Package Information to SPDX-TAG-VALUE Format
	for _, result := range results {
		spdxTagValues = append(spdxTagValues, fmt.Sprintf(
			"\n"+
				"##### Package: %s\n"+
				"\n"+
				"PackageName: %s\n"+
				"SPDXID: %s\n"+
				"PackageVersion: %s\n"+
				"PackageDownloadLocation: %s\n"+
				"FilesAnalyzed: %v\n"+
				"PackageLicenseConcluded: %s\n"+
				"PackageLicenseDeclared: %s\n"+
				"PackageCopyrightText: %s",
			result.Package.Name,                         // Package
			result.Package.Name,                         // PackageName
			spdxutils.FormatTagID(&result.Package),      // SPDXID
			result.Package.Version,                      // PackageVersion
			spdxutils.DownloadLocation(&result.Package), // PackageDownloadLocation
			false, // FilesAnalyzed
			spdxutils.LicensesDeclared(&result.Package), // PackageLicenseConcluded
			spdxutils.LicensesDeclared(&result.Package), // PackageLicenseDeclared
			spdxutils.NoAssertion,                       // PackageCopyrightText
		))

		for _, ref := range spdxutils.ExternalRefs(&result.Package) {
			spdxTagValues = append(spdxTagValues, fmt.Sprintf(
				"ExternalRef: %s %s %s",
				ref.ReferenceCategory,
				ref.ReferenceType,
				ref.ReferenceLocator,
			))
		}
	}

	return spdxTagValues
}

// PrintSpdxTagValue Print Packages in SPDX-TAG_VALUE format
func printSpdxTagValue() {
	spdxTagValues := GetSpdxTagValues()
	if len(*arguments.OutputFile) > 0 {
		saveResultToFile(stringSliceToString(spdxTagValues))
	} else {
		fmt.Printf("%+v", stringSliceToString(spdxTagValues))
	}
}

func stringSliceToString(slice []string) string {
	result := ""
	for _, s := range slice {
		result += fmt.Sprintln(s)
	}
	return result
}

func saveResultToFile(result string) {
	file, _ := os.Create(*arguments.OutputFile)
	os.WriteFile(file.Name(), []byte(result), 0644)
}
