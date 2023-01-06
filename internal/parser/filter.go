package parser

import (
	"strings"

	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/internal/model"

	"golang.org/x/exp/slices"
)

// List of Indexes to be removed from the list of packages
var indexes []int

// Check and locate and remove all of elements that matches the values based ignore policy in configuration
func Filter(packages *[]model.Package, ignore *config.Package) {

	if len(ignore.Name) > 0 {
		filterName(packages, ignore)
	}
	if len(ignore.Type) > 0 {
		filterType(packages, ignore)
	}
	if len(ignore.Version) > 0 {
		filterVersion(packages, ignore)
	}

	// Remove elements with index found in filter
	if len(indexes) > 0 {
		for i := len(indexes) - 1; i >= 0; i-- {
			indexToRemove := indexes[i]
			*packages = append((*packages)[:indexToRemove], (*packages)[indexToRemove+1:]...)
		}
	}
}

// Filter all package names listed in package ignore list
func filterName(packages *[]model.Package, ignore *config.Package) {
	for index, _package := range *packages {
		for _, name := range ignore.Name {
			if strings.Contains(name, ":") {
				parts := strings.Split(name, ":")
				if len(parts) > 1 {
					if strings.EqualFold(_package.Name, parts[0]) && strings.EqualFold(_package.Version, parts[1]) {
						if !slices.Contains(indexes, index) {
							indexes = append(indexes, index)
						}
					}
				}
			} else {
				if strings.EqualFold(_package.Name, name) {
					if !slices.Contains(indexes, index) {
						indexes = append(indexes, index)
					}
				}
			}
		}
	}
}

// Filter all package types listed in package ignore list
func filterType(packages *[]model.Package, ignore *config.Package) {
	for index, _package := range *packages {
		for _, _type := range ignore.Type {
			if strings.EqualFold(_package.Type, _type) {
				if !slices.Contains(indexes, index) {
					indexes = append(indexes, index)
				}
			}
		}
	}
}

// Filter all package versions listed in package ignore list
func filterVersion(packages *[]model.Package, ignore *config.Package) {
	for index, _package := range *packages {
		for _, version := range ignore.Version {
			if strings.EqualFold(_package.Version, version) {
				if !slices.Contains(indexes, index) {
					indexes = append(indexes, index)
				}
			}
		}
	}
}
