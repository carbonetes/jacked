package parser

import (
	"sort"

	"github.com/carbonetes/jacked/pkg/core/model"
)

func SortPackages(packages []model.Package) {
	sort.Slice(packages, func(i, j int) bool {
		return (packages)[i].Name < (packages)[j].Name
	})
}
