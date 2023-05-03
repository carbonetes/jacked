package metadata

import (
	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/pkg/core/model"
	metadata "github.com/carbonetes/jacked/pkg/core/model/metadata"

	"github.com/mitchellh/mapstructure"
	"golang.org/x/exp/slices"
)

// Parse package metadata and create keywords
func ParseAlpineMetadata(p *dm.Package, signature *model.Signature) {
	var metadata metadata.AlpineMetadata
	err := mapstructure.Decode(p.Metadata, &metadata)
	if err != nil {
		log.Errorln(err.Error())
	}
	// Create keywords from specified package name and origin on the metadata if they exist
	if len(metadata.PackageName) > 0 {
		if !slices.Contains(signature.Keywords, metadata.PackageName) {
			signature.Keywords = append(signature.Keywords, metadata.PackageName)
		}
	}
	if len(metadata.PackageOrigin) > 0 {
		if !slices.Contains(signature.Keywords, metadata.PackageOrigin) {
			signature.Keywords = append(signature.Keywords, metadata.PackageOrigin)
		}
	}
}
