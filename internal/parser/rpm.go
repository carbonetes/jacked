package parser

import (
	metadata "github.com/carbonetes/jacked/pkg/core/model/metadata"
	"github.com/carbonetes/jacked/pkg/core/model"

	"github.com/mitchellh/mapstructure"
	"golang.org/x/exp/slices"
)

// Parse package metadata and create keywords
func parseRpmMetadata(p *model.Package, keywords []string) []string {
	var metadata metadata.RpmMetadata
	err := mapstructure.Decode(p.Metadata, &metadata)
	if err != nil {
		log.Errorln(err.Error())
	}

	/* For keywords, we can only get the specified package name on metadata for rpm packages.
	 * But we can expand the accurary by adding more key values as keywords for each package
	 */
	if len(metadata.Name) > 0 {
		if !slices.Contains(keywords, metadata.Name) {
			keywords = append(keywords, metadata.Name)
		}
	}
	return keywords
}
