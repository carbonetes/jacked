package output

import (
	"encoding/json"
	"encoding/xml"
	"strconv"
	"time"

	"github.com/carbonetes/jacked/internal/model"
	"github.com/carbonetes/jacked/internal/version"

	cdx "github.com/carbonetes/jacked/internal/model"

	parser "github.com/carbonetes/jacked/internal/parser"

	"github.com/google/uuid"
)

const (
	vendor                                    = "carbonetes"
	name                                      = "jacked"
	jackedPrefix                              = "jacked"
	packagePrefix                             = "package"
	distroPrefix                              = "distro"
	colonPrefix                               = ":"
	cpePrefix                                 = "cpe23"
	locationPrefix                            = "location"
	library              cdx.ComponentLibrary = "library"
	operatingSystem                           = "operating-system"
	issueTracker                              = "issue-tracker"
	referenceWebsite                          = "website"
	referenceOther                            = "other"
	id                                        = ":id"
	prettyName                                = ":prettyName"
	distributionCodename                      = ":distributionCodename"
	versionID                                 = "versionID"
	support                                   = "support"
	privacyPolicy                             = "privacyPolicy"
	layerHash                                 = "layerHash"
	path                                      = "path"
	packageIdPrefix                           = "?package-id="
	// XMLN cyclonedx
	XMLN = "http://cyclonedx.org/schema/bom/1.4"
)

var (
	cdxOutputBOM    *cdx.BOM
	cdxOutputBOMVEX *cdx.BOMVEX
)

func PrintCycloneDX(formatType string, results []model.ScanResult) {

	switch formatType {

	// CycloneDX SBOM Vuln
	case "xml":
		cdxOutputBOM = convertPackage(results)
		result, _ := xml.MarshalIndent(cdxOutputBOM, "", " ")
		log.Printf("%+v\n", string(result))
	case "json":
		cdxOutputBOM = convertPackage(results)
		result, _ := json.MarshalIndent(cdxOutputBOM, "", " ")
		log.Printf("%+v\n", string(result))

	// CycloneDX VEX
	case "vex-json":
		cdxOutputBOMVEX = convertPackageVex(results)
		result, _ := json.MarshalIndent(cdxOutputBOMVEX, "", " ")
		log.Printf("%+v\n", string(result))
	case "vex-xml":
		cdxOutputBOMVEX = convertPackageVex(results)
		result, _ := xml.MarshalIndent(cdxOutputBOMVEX, "", " ")
		log.Printf("%+v\n", string(result))
	default:
		log.Error("Format type not found")
	}
}

func convertPackage(results []model.ScanResult) *cdx.BOM {

	// Create BOM component
	components := make([]cdx.Component, len(results))
	for i, result := range results {
		components[i] = convertToComponent(&result.Package, &result.Vulnerabilities)
	}

	components = append(components, addDistroComponent(parser.Distro()))

	return &cdx.BOM{
		BomFormat:    "CycloneDX",
		XMLNS:        XMLN,
		SerialNumber: uuid.NewString(),
		Metadata:     getFromSource(),
		Components:   &components,
	}
}

func addDistroComponent(distro *model.Distro) cdx.Component {

	if distro == nil {
		return cdx.Component{}
	}
	externalReferences := &[]cdx.ExternalReference{}
	if distro.BugReportURL != "" {
		*externalReferences = append(*externalReferences, cdx.ExternalReference{
			URL:  distro.BugReportURL,
			Type: issueTracker,
		})
	}
	if distro.HomeURL != "" {
		*externalReferences = append(*externalReferences, cdx.ExternalReference{
			URL:  distro.HomeURL,
			Type: referenceWebsite,
		})
	}
	if distro.SupportURL != "" {
		*externalReferences = append(*externalReferences, cdx.ExternalReference{
			URL:     distro.SupportURL,
			Type:    referenceOther,
			Comment: support,
		})
	}
	if distro.PrivacyPolicyURL != "" {
		*externalReferences = append(*externalReferences, cdx.ExternalReference{
			URL:     distro.PrivacyPolicyURL,
			Type:    referenceOther,
			Comment: privacyPolicy,
		})
	}
	if len(*externalReferences) == 0 {
		externalReferences = nil
	}
	properties := make([]cdx.Property, 0)

	// Assign ID
	properties = append(properties, cdx.Property{
		Name:  jackedPrefix + colonPrefix + distroPrefix + id,
		Value: distro.ID,
	})
	properties = append(properties, cdx.Property{
		Name:  jackedPrefix + colonPrefix + distroPrefix + prettyName,
		Value: distro.PrettyName,
	})
	properties = append(properties, cdx.Property{
		Name:  jackedPrefix + colonPrefix + distroPrefix + distributionCodename,
		Value: distro.DistribCodename,
	})
	properties = append(properties, cdx.Property{
		Name:  jackedPrefix + colonPrefix + distroPrefix + versionID,
		Value: distro.VersionID,
	})

	return cdx.Component{
		Type:               operatingSystem,
		Name:               distro.ID,
		Description:        distro.PrettyName,
		ExternalReferences: externalReferences,
		Properties:         &properties,
	}
}

func getFromSource() *cdx.Metadata {
	//temp data-- data should come from final bom model
	versionInfo := version.GetBuild()
	return &cdx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools: &[]cdx.Tool{
			{
				Vendor:  vendor,
				Name:    name,
				Version: versionInfo.Version,
			},
		},
	}
}

func convertToComponent(p *model.Package, vulns *[]model.Result) cdx.Component {
	return cdx.Component{
		BOMRef:          addID(p),
		Type:            library,
		Name:            p.Name,
		Version:         p.Version,
		PackageURL:      string(p.PURL),
		Vulnerabilities: vulns,
		Licenses:        convertLicense(p),
		Properties:      initProperties(p),
	}
}

func initProperties(p *model.Package) *[]cdx.Property {
	properties := make([]cdx.Property, 0)

	// Assign Type
	properties = append(properties, cdx.Property{
		Name:  jackedPrefix + colonPrefix + cpePrefix,
		Value: p.Type,
	})

	// Assign CPEs
	for _, cpe := range p.CPEs {
		properties = append(properties, cdx.Property{
			Name:  jackedPrefix + colonPrefix + cpePrefix,
			Value: cpe,
		})
	}

	// Assign Location
	for i, location := range p.Locations {
		index := strconv.Itoa(i)

		// Add Hash
		properties = append(properties, cdx.Property{
			Name:  jackedPrefix + colonPrefix + locationPrefix + colonPrefix + index + colonPrefix + layerHash,
			Value: location.LayerHash,
		})

		//Add Path
		properties = append(properties, cdx.Property{
			Name:  jackedPrefix + colonPrefix + locationPrefix + colonPrefix + index + colonPrefix + path,
			Value: location.Path,
		})
	}
	return &properties
}

func addID(p *model.Package) string {
	return string(p.PURL) + packageIdPrefix + p.ID
}

func convertLicense(p *model.Package) *[]cdx.Licensecdx {

	licenses := make([]cdx.Licensecdx, 0)
	for _, licenseName := range p.Licenses {
		licenses = append(licenses, cdx.Licensecdx{
			ID: licenseName,
		})
	}
	if len(licenses) > 0 {
		return &licenses
	}
	return nil
}

// Vex Functionality

func convertToComponentVex(p *model.Package, vulns *[]model.Result) cdx.ComponentVEX {

	response := []string{"will_not_fix", "update"}
	return cdx.ComponentVEX{
		Type:               library,
		Name:               p.Name,
		Version:            p.Version,
		PackageURL:         string(p.PURL),
		VulnerabilitiesVEX: parseVex(vulns),
		AnalysisVEX: cdx.AnalysisVEX{
			State:         "",
			Justification: "",
			Response:      response,
			Detail:        "",
		},
		Affects: parseAffectsVEX(vulns),
	}
}

func parseVex(vulns *[]model.Result) []cdx.VulnerabilityVEX {
	vexs := make([]cdx.VulnerabilityVEX, 0)
	for _, vuln := range *vulns {
		vexs = append(vexs, cdx.VulnerabilityVEX{
			VulnerabilityID: vuln.CVE,
			Source: cdx.SourceVEX{
				Name: "NVD",
				Url:  "https://nvd.nist.gov/vuln/detail/" + vuln.CVE,
			},
			Description: vuln.Description,
			BaseScore:   vuln.CVSS.BaseScore,
			Severity:    vuln.CVSS.Severity,
			RatingsVEX:  parseRatingsVEX(vulns),
		})
	}
	return vexs
}

func convertPackageVex(results []model.ScanResult) *cdx.BOMVEX {

	// Create BOM component
	components := make([]cdx.ComponentVEX, len(results))
	for i, result := range results {
		components[i] = convertToComponentVex(&result.Package, &result.Vulnerabilities)
	}

	return &cdx.BOMVEX{
		BomFormat:    "CycloneDX",
		XMLNS:        XMLN,
		SerialNumber: uuid.NewString(),
		Metadata:     getFromSource(),
		Components:   &components,
	}
}

func parseRatingsVEX(vulns *[]model.Result) []cdx.RatingVEX {
	ratingsVEX := make([]cdx.RatingVEX, 0)
	for _, vuln := range *vulns {
		ratingsVEX = append(ratingsVEX, cdx.RatingVEX{
			SourceVEX: cdx.SourceVEX{
				Name: "NVD",
				Url:  "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N&version=3.1",
			},
			BaseScore: vuln.CVSS.BaseScore,
			Severity:  vuln.CVSS.Severity,
		})
	}
	return ratingsVEX
}

func parseAffectsVEX(vulns *[]model.Result) []cdx.Affect {
	affectsVEX := make([]cdx.Affect, 0)
	for _, vuln := range *vulns {
		affectsVEX = append(affectsVEX, cdx.Affect{
			Ref: "urn:cdx:2c385cf7-e1ee-46e9-a51c-13de1ecb380a/1#acme-product-1" + vuln.Package,
		})
	}
	return affectsVEX
}
