package parser

import (
	"strings"

	"github.com/carbonetes/jacked/internal/model"
	metadata "github.com/carbonetes/jacked/internal/model/metadata"

	"github.com/mitchellh/mapstructure"
	"golang.org/x/exp/slices"
)

// Parse package metadata and create keywords and possible indicates the exact vendor for the package
func parseJavaMetadata(p *model.Package) *model.Package {
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
			p.Vendor = "vmware"
			if p.Name == "spring-core" {
				p.Keywords = append(p.Keywords, "spring_framework")
			}
		}
		if strings.Contains(groupId, "amazonaws") {
			p.Vendor = "amazon"
		}
		if strings.Contains(groupId, "apache") {
			p.Vendor = "apache"
		}
	}

	if strings.Contains(p.Name, "log4j") {
		p.Keywords = append(p.Keywords, "log4j")
	}

	if strings.Contains(p.Name, "snakeyaml") {
		p.Vendor = "snakeyaml_project"
	}

	//TODO: add more corrections for packages that doesn't have clear vendor for cpe and metadata for keywords.

	var packageName string
	if len(metadata.PomProject.Name) > 0 {
		packageName = metadata.PomProject.Name
	}

	if len(metadata.PomProperties.Name) > 0 {
		packageName = metadata.PomProperties.Name
	}

	if len(packageName) > 0 && !slices.Contains(p.Keywords, packageName) {
		p.Keywords = append(p.Keywords, packageName)
	}

	return p
}
