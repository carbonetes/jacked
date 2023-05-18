package sbom

import (
	"strings"

	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/internal/config"

	"golang.org/x/exp/slices"
)

// List of Indexes to be removed from the list of packages
var (
	indexes              []int
	enabledFilterName    bool
	enabledFilterType    bool
	enabledFilterVersion bool
)

// Check and locate and remove all of elements that matches the values based ignore policy in configuration
func Filter(packages *[]dm.Package, ignore *config.Package) {

	enabledFilterName = len(ignore.Name) > 0
	enabledFilterType = len(ignore.Type) > 0
	enabledFilterVersion = len(ignore.Version) > 0

	// Filter Loop
	if enabledFilterName || enabledFilterType || enabledFilterVersion {
		filterPackage(packages, ignore)
	}

	// Remove elements with index found in filter
	if len(indexes) > 0 {
		for i := len(indexes) - 1; i >= 0; i-- {
			indexToRemove := indexes[i]
			*packages = append((*packages)[:indexToRemove], (*packages)[indexToRemove+1:]...)
		}
	}
}

func filterPackage(packages *[]dm.Package, ignore *config.Package) {
	for index, p := range *packages {

		// Filter By Name
		if enabledFilterName {
			filterName(index, &p, ignore)
		}

		// Filter By Type
		if enabledFilterType {
			filterType(index, &p, ignore)
		}

		// Filter By Version
		if enabledFilterVersion {
			filterVersion(index, &p, ignore)
		}
	}
}

// Filter all package names listed in package ignore list
func filterName(index int, _package *dm.Package, ignore *config.Package) {

	for _, name := range ignore.Name {
		if strings.EqualFold(_package.Name, name) {
			if !slices.Contains(indexes, index) {
				indexes = append(indexes, index)
			}
		}
	}

}

// Filter all package types listed in package ignore list
func filterType(index int, _package *dm.Package, ignore *config.Package) {
	for _, _type := range ignore.Type {
		if strings.EqualFold(_package.Type, _type) {
			if !slices.Contains(indexes, index) {
				indexes = append(indexes, index)
			}
		}
	}
}

// Filter all package versions listed in package ignore list
func filterVersion(index int, _package *dm.Package, ignore *config.Package) {
	for _, version := range ignore.Version {
		if strings.EqualFold(_package.Version, version) {
			if !slices.Contains(indexes, index) {
				indexes = append(indexes, index)
			}
		}
	}
}
