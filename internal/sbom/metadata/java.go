package metadata

import (
	"strings"

	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/pkg/core/model"
	metadata "github.com/carbonetes/jacked/pkg/core/model/metadata"

	"github.com/mitchellh/mapstructure"
	"golang.org/x/exp/slices"
)

var log = logger.GetLogger()

// Parse package metadata and create keywords and possible indicates the exact vendor for the package
func ParseJavaMetadata(p *dm.Package, signature *model.Signature) {
	var metadata metadata.JavaMetadata
	err := mapstructure.Decode(p.Metadata, &metadata)
	if err != nil {
		log.Errorln(err.Error())
	}

	// Corrections for selected packages
	var groupId string
	if len(metadata.PomProject.GroupID) > 0 {
		groupId = metadata.PomProject.GroupID
	}
	if len(metadata.PomProperties.GroupId) > 0 {
		groupId = metadata.PomProperties.GroupId
	}
	if len(groupId) > 0 {
		if strings.Contains(groupId, "springframework") {
			signature.Vendor = append(signature.Vendor, "vmware")
			if p.Name == "spring-core" {
				signature.Keywords = append(signature.Keywords, "spring_framework")
			}
		}
		if strings.Contains(groupId, "amazonaws") {
			signature.Vendor = append(signature.Vendor, "vmware")
		}
		if strings.Contains(groupId, "apache") {
			signature.Vendor = append(signature.Vendor, "vmware")
		}
	}

	if strings.Contains(p.Name, "log4j") {
		signature.Keywords = append(signature.Keywords, "log4j")
	}

	if strings.Contains(p.Name, "snakeyaml") {
		signature.Vendor = append(signature.Vendor, "snakeyaml_project")
	}

	//TODO: add more corrections for packages that doesn't have clear vendor for cpe and metadata for keywords.

	var packageName string
	if len(metadata.PomProject.Name) > 0 {
		packageName = metadata.PomProject.Name
	}

	if len(metadata.PomProperties.Name) > 0 {
		packageName = metadata.PomProperties.Name
	}

	if len(packageName) > 0 && !slices.Contains(signature.Keywords, packageName) {
		signature.Keywords = append(signature.Keywords, packageName)
	}
}
