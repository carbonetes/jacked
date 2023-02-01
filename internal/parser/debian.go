package parser

import (
	"github.com/carbonetes/jacked/internal/model"
	metadata "github.com/carbonetes/jacked/internal/model/metadata"

	"github.com/mitchellh/mapstructure"
	"golang.org/x/exp/slices"
)

// Parse package metadata and create keywords
func parseDebianMetadata(p *model.Package, keywords []string) []string {
	var metadata metadata.DebianMetadata
	err := mapstructure.Decode(p.Metadata, &metadata)
	if err != nil {
		log.Errorln(err.Error())
	}
	// Create keyword based on the value of source in package metadata if it exist
	if len(metadata.Source) > 0 {
		if !slices.Contains(keywords, metadata.Source) {
			keywords = append(keywords, metadata.Source)
		}
	}
	return keywords
}
