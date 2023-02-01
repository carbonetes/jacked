package parser

import (
	"github.com/carbonetes/jacked/internal/model"
	metadata "github.com/carbonetes/jacked/internal/model/metadata"

	"github.com/mitchellh/mapstructure"
	"golang.org/x/exp/slices"
)

// Parse package metadata and create keywords
func parseAlpineMetadata(p *model.Package, keywords []string) []string {
	var metadata metadata.AlpineMetadata
	err := mapstructure.Decode(p.Metadata, &metadata)
	if err != nil {
		log.Errorln(err.Error())
	}
	// Create keywords from specified package name and origin on the metadata if they exist
	if len(metadata.PackageName) > 0 {
		if !slices.Contains(keywords, metadata.PackageName) {
			keywords = append(keywords, metadata.PackageName)
		}
	}
	if len(metadata.PackageOrigin) > 0 {
		if !slices.Contains(keywords, metadata.PackageOrigin) {
			keywords = append(keywords, metadata.PackageOrigin)
		}
	}

	return keywords
}
