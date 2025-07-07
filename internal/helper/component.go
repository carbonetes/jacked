package helper

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
)

// SplitCpe splits a CPE string into its parts.
func SplitCpe(cpe string) []string {
	// Split the CPE string into its components.
	// The components are separated by colons.
	return strings.Split(cpe, ":")
}

// GetComponentType returns the type of a component.
func GetComponentType(props *[]cyclonedx.Property) string {
	// Return nil if the properties are nil.
	if props == nil {
		return "unknown"
	}

	// Loop through the component properties to find the "diggity:package:type" property.
	for _, prop := range *props {
		if prop.Name == "diggity:package:type" {
			return prop.Value
		}
	}

	// Return nil if the property was not found.
	return "unknown"
}

func FindUpstream(target string) string {
	purl, err := packageurl.FromString(target)
	if err != nil {
		return ""
	}

	if len(purl.Qualifiers) == 0 {
		return ""
	}

	for _, qualifier := range purl.Qualifiers {
		if qualifier.Key == "upstream" {
			return qualifier.Value
		}
	}

	return ""
}

func FindPackageType(props *[]cyclonedx.Property, name string) *string {
	// Return nil if the properties are nil.
	if props == nil {
		return nil
	}

	// Loop through the component properties to find the "diggity:package:type" property.
	for _, prop := range *props {
		if prop.Name == name {
			return &prop.Value
		}
	}

	// Return nil if the property was not found.
	return nil
}
