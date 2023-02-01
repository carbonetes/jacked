package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"time"

	"github.com/carbonetes/jacked/internal/logger"
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

var log = logger.GetLogger()

func PrintCycloneDX(formatType string, results []model.ScanResult) {
	cyclonedxOuput := convertPackage(results)

	switch formatType {
	case "xml":
		result, err := xml.MarshalIndent(cyclonedxOuput, "", " ")
		if err != nil {
			log.Errorln(err.Error())
		}
		fmt.Printf("%+v\n", string(result))
	case "json":
		result, err := json.MarshalIndent(cyclonedxOuput, "", " ")
		if err != nil {
			log.Errorln(err.Error())
		}
		fmt.Printf("%+v\n", string(result))
	default:
		fmt.Printf("Format type not found")
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
