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
	// CVSS Method
	OtherMethod   string = "other"
	CVSSv2Method  string = "CVSSv2"
	CVSSv3Method  string = "CVSSv3"
	CVSSv31Method string = "CVSSv31"
)

var (
	cdxOutputBOM *cdx.BOM
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
		cdxOutputBOM = convertPackage(results)
		result, _ := json.MarshalIndent(cdxOutputBOM, "", " ")
		log.Printf("%+v\n", string(result))
	case "vex-xml":
		cdxOutputBOM = convertPackage(results)
		result, _ := xml.MarshalIndent(cdxOutputBOM, "", " ")
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
		VEX:          parseVexBOM(results),
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
func parseVexBOM(results []model.ScanResult) []cdx.VexBOM {
	vexsBOM := make([]cdx.VexBOM, 0)
	for _, result := range results {
		p := result.Package

		for _, vuln := range result.Vulnerabilities {
			vexsBOM = append(vexsBOM, cdx.VexBOM{
				BomRef: uuid.NewString(),
				ID:     vuln.CVE,
				SourceVEX: cdx.SourceVEX{
					Name: vuln.Package,
					Url:  "",
				},
				RatingVEX: parseRatingsVEX(vuln),
				Affects: []cdx.Affect{
					{
						Ref: string(p.PURL),
					},
				},
			})
		}
	}
	return vexsBOM
}

func convertPackageVex(results []model.ScanResult) *cdx.BOM {

	// Create SBOM component and VEX
	components := make([]cdx.Component, len(results))
	for i, result := range results {
		components[i] = convertToComponent(&result.Package, nil)
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

func parseRatingsVEX(vuln cdx.Result) cdx.RatingVEX {

	return cdx.RatingVEX{
		SourceVEX: cdx.SourceVEX{
			Name: vuln.Package,
			Url:  "",
		},
		Description: vuln.Description,
		BaseScore:   vuln.CVSS.BaseScore,
		Severity:    vuln.CVSS.Severity,
		Method:      cvssMethod(vuln.CVSS.Version),
		Vector:      "",
	}
}

func cvssMethod(version string) string {
	value, err := strconv.ParseFloat(version, 64)
	if err != nil {
		return ""
	}

	switch value {
	case 2:
		return CVSSv2Method
	case 3:
		return CVSSv3Method
	case 3.1:
		return CVSSv31Method
	default:
		return OtherMethod
	}
}
