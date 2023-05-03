package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"

	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/internal/logger"
	spdxutils "github.com/carbonetes/jacked/internal/output/spdx-utils"
	"github.com/carbonetes/jacked/pkg/core/model"
)

var log = logger.GetLogger()

func PrintSPDX(formatType string, image *string, sbom *dm.SBOM) {

	spdx := GetSpdx(image, sbom.Packages)

	switch formatType {
	case "xml":
		result, err := xml.MarshalIndent(spdx, "", " ")
		if err != nil {
			log.Errorln(err.Error())
		}
		fmt.Printf("%+v\n", string(result))
	case "json":
		result, err := json.MarshalIndent(spdx, "", " ")
		if err != nil {
			log.Errorln(err.Error())
		}
		fmt.Printf("%+v\n", string(result))
	case "tag-value":
		printSpdxTagValue(image, sbom.Packages)
	default:
		log.Error("Format type not found")
		os.Exit(1)
	}
}

func GetSpdx(image *string, pkgs *[]dm.Package) model.SpdxDocument {

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
		SpdxPackages:      spdxPackages(pkgs),
	}
	return result
}

// spdxJSONPackages Get Packages in SPDX-JSON format
func spdxPackages(pkgs *[]dm.Package) (spdxPkgs []model.SpdxPackage) {

	for _, p := range *pkgs {
		spdxPkgs = append(spdxPkgs, model.SpdxPackage{
			SpdxID:           spdxutils.Ref + p.ID,
			Name:             p.Name,
			Description:      p.Description,
			DownloadLocation: spdxutils.DownloadLocation(&p),
			LicenseConcluded: spdxutils.LicensesDeclared(&p),
			ExternalRefs:     spdxutils.ExternalRefs(&p),
			FilesAnalyzed:    false, // If false, indicates packages that represent metadata or URI references to a project, product, artifact, distribution or a component.
			Homepage:         spdxutils.Homepage(&p),
			LicenseDeclared:  spdxutils.LicensesDeclared(&p),
			Originator:       spdxutils.Originator(&p),
			SourceInfo:       spdxutils.SourceInfo(&p),
			VersionInfo:      p.Version,
			Copyright:        spdxutils.NoAssertion,
			Vulnerabilities:  *p.Vulnerabilities,
		})
	}
	return spdxPkgs
}

// GetSpdxTagValues Parse SPDX-TAG_VALUE format
func GetSpdxTagValues(image *string, pkgs *[]dm.Package) (spdxTagValues []string) {
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
		spdxutils.Version,                                      // SPDXVersion
		spdxutils.DataLicense,                                  // DataLicense
		spdxutils.Ref+spdxutils.Doc,                            // SPDXID
		spdxutils.FormatName(image),                            // DocumentName
		spdxutils.FormatNamespace(spdxutils.FormatName(image)), // DocumentNamespace
		spdxutils.LicenseListVersion,                           // LicenseListVersion
		spdxutils.Creator,                                      // Creator: Organization
		spdxutils.Tool,                                         // Creator: Tool
		time.Now().UTC().Format(time.RFC3339),                  // Created
	))

	// Parse Package Information to SPDX-TAG-VALUE Format
	for _, p := range *pkgs {
		var cves []string
		for _, v := range *p.Vulnerabilities {
			cves = append(cves, v.CVE)
		}

		spdxTagValues = append(spdxTagValues, fmt.Sprintf(
			"\n##### Package: %s\n\n"+
				"PackageName: %s\n"+
				"SPDXID: %s\n"+
				"PackageVersion: %s\n"+
				"PackageDownloadLocation: %s\n"+
				"FilesAnalyzed: %t\n"+
				"PackageLicenseConcluded: %s\n"+
				"PackageLicenseDeclared: %s\n"+
				"PackageCopyrightText: %s\n"+
				"Vulnerabilities: %v",
			p.Name,                         // Package
			p.Name,                         // PackageName
			spdxutils.FormatTagID(&p),      // SPDXID
			p.Version,                      // PackageVersion
			spdxutils.DownloadLocation(&p), // PackageDownloadLocation
			false, // FilesAnalyzed
			spdxutils.LicensesDeclared(&p), // PackageLicenseConcluded
			spdxutils.LicensesDeclared(&p), // PackageLicenseDeclared
			spdxutils.NoAssertion,                       // PackageCopyrightText
			formatCVEList(cves),                         // Vulnerabilities
		))

		for _, ref := range spdxutils.ExternalRefs(&p) {
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
func printSpdxTagValue(image *string, pkgs *[]dm.Package) {
	spdxTagValues := GetSpdxTagValues(image, pkgs)
	fmt.Printf("%+v", stringSliceToString(spdxTagValues))

}

func formatCVEList(cves []string) string {
	if len(cves) == 0 {
		return spdxutils.None
	}
	return strings.Join(cves, ",")
}

func stringSliceToString(slice []string) string {
	result := ""
	for _, s := range slice {
		result += fmt.Sprintln(s)
	}
	return result
}
