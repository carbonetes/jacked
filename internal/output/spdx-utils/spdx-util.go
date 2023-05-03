package spdxutils

import (
	"fmt"
	"os"
	"strings"

	"github.com/carbonetes/jacked/internal/version"
	"github.com/carbonetes/jacked/pkg/core/model"

	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/google/uuid"

	metadata "github.com/carbonetes/jacked/pkg/core/model/metadata"
)

const (
	// Version : current implemented version (2.2)
	Version = "SPDX-2.2"
	// DataLicense : 6.2 Data license field Table 3 https://spdx.github.io/spdx-spec/v2.2.2/document-creation-information/
	DataLicense = "CC0-1.0"
	// Creator : Organization: Carbonetes
	Creator = "Organization: Carbonetes"
	// Ref : SPDX Ref Prefix
	Ref = "SPDXRef-"
	// Doc : Document Prefix
	Doc = "DOCUMENT"
	// NoAssertion : NO ASSERTION (For licenses)
	NoAssertion = "NOASSERTION"
	// None : NONE
	None = "NONE"

	security         = "SECURITY"
	cpeType          = "cpe23Type"
	purlType         = "purl"
	packageManager   = "PACKAGE_MANAGER"
	licenseSeparator = " AND "
	parsedFrom       = "Information parsed from"
	namespace        = "https://console.carbonetes.com/diggity/image/"
	url              = "https://spdx.org/licenses/licenses.json"
)

// CreateInfo : Contains creator and tool information.
var (
	Tool       = "Tool: " + version.GetBuild().Version
	CreateInfo = []string{Creator, Tool}
)

// FormatName helper
func FormatName(image *string) string {
	if strings.Contains(*image, ":") {
		return strings.Split(*image, ":")[0]
	}
	return *image
}

// FormatNamespace helper
func FormatNamespace(imageName string) string {
	return namespace + imageName + "-" + uuid.NewString()
}

// FormatPath helper
func FormatPath(path string) string {
	pathSlice := strings.Split(path, string(os.PathSeparator))
	return strings.Join(pathSlice, "/")
}

// FormatTagID helper
func FormatTagID(p *dm.Package) string {
	return fmt.Sprintf("%sPackage-%+v-%s-%s", Ref, p.Type, p.Name, p.ID)
}

// CheckLicense helper
func CheckLicense(id string) string {
	license := LicenseList[strings.ToLower(id)]
	return license
}

// DownloadLocation helper
func DownloadLocation(p *dm.Package) string {
	var url string

	switch m := p.Metadata.(type) {
	case metadata.AlpineManifest:
		if val, ok := m["PackageURL"]; ok {
			url = val.(string)
		}
	case metadata.PackageJSON:
		switch m.Repository.(type) {
		case map[string]interface{}:
			repo := m.Repository.(map[string]interface{})
			if _, ok := repo["url"]; ok {
				url = repo["url"].(string)
			}
		case string:
			url = m.Repository.(string)
		}
	default:
		return NoAssertion
	}

	if strings.TrimSpace(url) == "" {
		return None
	}

	return url
}

// LicensesDeclared helper
func LicensesDeclared(p *dm.Package) string {
	// Check if package has licenses
	if len(p.Licenses) <= 0 {
		return None
	}

	var licenses []string

	// Validate Licenses from License List
	for _, license := range p.Licenses {
		if CheckLicense(license) != "" {
			licenses = append(licenses, license)
		}
	}

	if len(licenses) > 0 {
		return strings.Join(licenses, licenseSeparator)
	}

	return NoAssertion

}

// ExternalRefs helper
func ExternalRefs(p *dm.Package) (refs []model.ExternalRef) {
	// Init CPEs
	for _, cpe := range p.CPEs {
		var cpeRef model.ExternalRef
		cpeRef.ReferenceCategory = security
		cpeRef.ReferenceLocator = cpe
		cpeRef.ReferenceType = cpeType
		refs = append(refs, cpeRef)
	}

	// Init PURL
	var purlRef model.ExternalRef
	purlRef.ReferenceCategory = packageManager
	purlRef.ReferenceLocator = string(p.PURL)
	purlRef.ReferenceType = purlType
	refs = append(refs, purlRef)

	return refs
}

// Homepage helper
func Homepage(p *dm.Package) string {
	switch m := p.Metadata.(type) {
	case metadata.PackageJSON:
		return m.Homepage
	case metadata.GemMetadata:
		if val, ok := m["homepage"]; ok {
			return val.(string)
		}
	}
	return ""
}

// Originator helper
func Originator(p *dm.Package) string {
	var originator string

	switch m := p.Metadata.(type) {
	// Cases with existing metadata models
	case metadata.RpmMetadata:
		originator = fmt.Sprintf("Organization: %s", m.Vendor)
		return originator
	case metadata.PackageJSON:
		switch m.Author.(type) {
		case map[string]interface{}:
			author := m.Author.(map[string]interface{})
			authorDetails := []string{}

			if val, ok := author["name"]; ok {
				authorDetails = append(authorDetails, val.(string))
			}
			if val, ok := author["email"]; ok {
				authorDetails = append(authorDetails, val.(string))
			}
			originator = strings.Join(authorDetails, " ")
		case string:
			author := m.Author.(string)
			originator = FormatAuthor(author)
		}

	// Cases with metadata declared within the parser
	case metadata.AlpineManifest:
		if val, ok := m["Maintainer"]; ok {
			originator = val.(string)
		}
	case metadata.PythonMetadata:
		if val, ok := m["Author"]; ok {
			originator = val.(string)
		}
	case metadata.DebianMetadataParser:
		if val, ok := m["Maintainer"]; ok {
			originator = val.(string)
		}
	case metadata.GemMetadata:
		if val, ok := m["authors"]; ok {
			originator = val.([]string)[0]
		}
	}

	if originator != "" {
		return fmt.Sprintf("Person: %s", originator)
	}

	return ""
}

// FormatAuthor helper
func FormatAuthor(authorString string) string {
	author := []string{}

	// Check for empty author
	if strings.TrimSpace(authorString) == "" {
		return ""
	}

	authorDetails := strings.Split(authorString, " ")
	if len(authorDetails) == 1 {
		return authorDetails[0]
	}

	for _, detail := range authorDetails {
		if strings.Contains(detail, "http") && strings.Contains(detail, ".") && strings.Contains(detail, "/") {
			continue
		}
		author = append(author, detail)
	}

	return strings.Join(author, " ")
}

// SourceInfo helper
func SourceInfo(p *dm.Package) string {
	var source string
	var locations []string

	switch p.Type {
	case "apk":
		source = "APK DB"
	case "php":
		source = "PHP composer manifest"
	case "pub":
		source = "pubspec manifest"
	case "deb":
		source = "DPKG DB"
	case "gem":
		source = "gem metadata"
	case "go-module":
		source = "go-module information"
	case "java":
		source = "java archive"
	case "npm":
		source = "node module manifest"
	case "dotnet":
		source = "dotnet project assets"
	case "python":
		source = "python package manifest"
	case "rpm":
		source = "RPM DB"
	default:
		source = ""
	}

	if len(p.Locations) > 0 {
		for _, loc := range p.Locations {
			locations = append(locations, FormatPath(loc.Path))
		}
	}

	return fmt.Sprintf("%s %s: %s", parsedFrom, source, strings.Join(locations, ", "))
}
