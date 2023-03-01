package model

import "time"

type SpdxDocument struct {
	SPDXID            string       `json:"SPDXID" xml:"SPDXID"`
	Name              string       `json:"name,omitempty"  xml:"name,omitempty"`
	SpdxVersion       string       `json:"spdxVersion"  xml:"spdxVersion,omitempty"`
	CreationInfo      CreationInfo `json:"creationInfo"  xml:"creationInfo,omitempty"`
	DataLicense       string       `json:"dataLicense" xml:"dataLicense,omitempty"`
	DocumentNamespace string       `json:"documentNamespace"  xml:"documentNamespace,omitempty"`
	// SpdxJsonPackages Actual Packages
	SpdxPackages []SpdxPackage `json:"packages,omitempty" xml:"packages>package,omitempty"`
}

type SpdxPackage struct {
	SpdxID           string        `json:"SPDXID" xml:"SPDXID,omitempty"`
	Name             string        `json:"name,omitempty" xml:"name,omitempty"`
	LicenseConcluded string        `json:"licenseConcluded,omitempty" xml:"licenseConcluded,omitempty"`
	Description      string        `json:"description,omitempty" xml:"description,omitempty"`
	DownloadLocation string        `json:"downloadLocation,omitempty" xml:"downloadLocation,omitempty"`
	ExternalRefs     []ExternalRef `json:"externalRefs,omitempty" xml:"externalRefs>externalRef,omitempty"`
	FilesAnalyzed    bool          `json:"filesAnalyzed" xml:"filesAnalyzed"`
	Homepage         string        `json:"homepage,omitempty" xml:"homepage,omitempty"`
	LicenseDeclared  string        `json:"licenseDeclared,omitempty" xml:"licenseDeclared,omitempty"`
	Originator       string        `json:"originator,omitempty" xml:"originator,omitempty"`
	SourceInfo       string        `json:"sourceInfo,omitempty" xml:"sourceInfo,omitempty"`
	VersionInfo      string        `json:"versionInfo,omitempty" xml:"versionInfo,omitempty"`
	Copyright        string        `json:"copyright,omitempty"  xml:"copyright,omitempty"`
	Vulnerabilities  []Result      `json:"vulnerabilities,omitempty" xml:"vulnerabilities>vulnerability,omitempty"`
}

// ExternalRef Model
type ExternalRef struct {
	ReferenceCategory string `json:"referenceCategory,omitempty"  xml:"referenceCategory,omitempty"`
	ReferenceLocator  string `json:"referenceLocator,omitempty" xml:"referenceLocator,omitempty"`
	ReferenceType     string `json:"referenceType,omitempty" xml:"referenceType,omitempty"`
}

// CreationInfo Model
type CreationInfo struct {
	Created            time.Time `json:"created" xml:"created"`
	Creators           []string  `json:"creators" xml:"creators"`
	LicenseListVersion string    `json:"licenseListVersion" xml:"licenseListVersion"`
}
