package core

import (
	"slices"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/helper"
)

// TypeBasedFilter filters components based on their type
type TypeBasedFilter struct {
	supportedTypes []string
	excludedTypes  []string
}

// NewTypeBasedFilter creates a new type-based filter (factory method)
func NewTypeBasedFilter(supportedTypes []string, excludedTypes []string) *TypeBasedFilter {
	return &TypeBasedFilter{
		supportedTypes: supportedTypes,
		excludedTypes:  excludedTypes,
	}
}

// Filter filters components based on their type
func (f *TypeBasedFilter) Filter(components []cyclonedx.Component) []cyclonedx.Component {
	if len(f.supportedTypes) == 0 && len(f.excludedTypes) == 0 {
		return components
	}

	var filtered []cyclonedx.Component
	for _, comp := range components {
		componentType := f.getComponentType(comp)

		// Skip if type is excluded
		if len(f.excludedTypes) > 0 && slices.Contains(f.excludedTypes, componentType) {
			continue
		}

		// Include if no supported types specified, or if type is in supported list
		if len(f.supportedTypes) == 0 || slices.Contains(f.supportedTypes, componentType) {
			filtered = append(filtered, comp)
		}
	}

	return filtered
}

// SupportsType checks if the filter supports a given component type
func (f *TypeBasedFilter) SupportsType(componentType string) bool {
	if len(f.excludedTypes) > 0 && slices.Contains(f.excludedTypes, componentType) {
		return false
	}

	if len(f.supportedTypes) == 0 {
		return true
	}

	return slices.Contains(f.supportedTypes, componentType)
}

// getComponentType extracts the component type from properties
func (f *TypeBasedFilter) getComponentType(comp cyclonedx.Component) string {
	if comp.Properties != nil {
		for _, prop := range *comp.Properties {
			if prop.Name == "component:type" {
				return prop.Value
			}
		}
	}

	// Fallback to helper function if available
	if comp.Properties != nil {
		return helper.GetComponentType(comp.Properties)
	}

	return "unknown"
}
