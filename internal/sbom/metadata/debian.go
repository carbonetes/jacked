package metadata

import (
	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/pkg/core/model"
	metadata "github.com/carbonetes/jacked/pkg/core/model/metadata"
	"golang.org/x/exp/slices"

	"github.com/mitchellh/mapstructure"
)

// Parse package metadata and create keywords
func ParseDebianMetadata(p *dm.Package, signature *model.Signature) {
	var metadata metadata.DebianMetadata
	err := mapstructure.Decode(p.Metadata, &metadata)
	if err != nil {
		log.Errorln(err.Error())
	}
	// Create keyword based on the value of source in package metadata if it exist
	if len(metadata.Source) > 0 {
		if !slices.Contains(signature.Keywords, metadata.Source) {
			signature.Keywords = append(signature.Keywords, metadata.Source)
		}
	}
}