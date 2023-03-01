package model

import "encoding/xml"

type BOMReference string

type ComponentType string

const (
	ComponentTypeApplication ComponentType = "application"
	ComponentTypeContainer   ComponentType = "container"
	ComponentTypeDevice      ComponentType = "device"
	ComponentTypeFile        ComponentType = "file"
	ComponentTypeFirmware    ComponentType = "firmware"
	ComponentTypeFramework   ComponentType = "framework"
	ComponentTypeLibrary     ComponentType = "library"
	ComponentTypeOS          ComponentType = "operating-system"
)

//CycloneFormat - CycloneDX Output Model
type BOM struct {
	// SBOM
	BomFormat    string       `json:"bomFormat" xml:"bomFormat"`
	XMLName      xml.Name     `json:"-" xml:"bom"`
	XMLNS        string       `json:"-" xml:"xmlns,attr"`
	SerialNumber string       `json:"serialNumber,omitempty" xml:"serialNumber,attr,omitempty"`
	Metadata     *Metadata    `json:"metadata,omitempty" xml:"metadata,omitempty"`
	Components   *[]Component `json:"components,omitempty" xml:"components>component,omitempty"`
	VEX          []VexBOM     `json:"vex,omitempty" xml:"vexs>vex,omitempty"` // VEX
}

// Metadata - cyclone format metadata
type Metadata struct {
	Timestamp  string      `json:"timestamp,omitempty" xml:"timestamp,omitempty"`
	Tools      *[]Tool     `json:"tools,omitempty" xml:"tools>tool,omitempty"`
	Component  *Component  `json:"component,omitempty" xml:"component,omitempty"`
	Licenses   *[]License  `json:"licenses,omitempty" xml:"licenses>license,omitempty"`
	Properties *[]Property `json:"properties,omitempty" xml:"properties>property,omitempty"`
}

// Tool - metadata tool
type Tool struct {
	Vendor  string `json:"vendor,omitempty" xml:"vendor,omitempty"`
	Name    string `json:"name" xml:"name"`
	Version string `json:"version,omitempty" xml:"version,omitempty"`
}

//ComponentLibrary - component library type
type ComponentLibrary string

// OperatingSystem - operating system type
type OperatingSystem string

// Component - CycloneFormat component
type Component struct {
	BOMRef             string               `json:"bom-ref,omitempty" xml:"bom-ref,attr,omitempty"`
	MIMEType           string               `json:"mime-type,omitempty" xml:"mime-type,attr,omitempty"`
	Type               ComponentLibrary     `json:"type" xml:"type,attr"`
	Author             string               `json:"author,omitempty" xml:"author,omitempty"`
	Publisher          string               `json:"publisher,omitempty" xml:"publisher,omitempty"`
	Group              string               `json:"group,omitempty" xml:"group,omitempty"`
	Name               string               `json:"name" xml:"name"`
	Version            string               `json:"version,omitempty" xml:"version,omitempty"`
	Description        string               `json:"description,omitempty" xml:"description,omitempty"`
	Licenses           *[]Licensecdx        `json:"licenses,omitempty" xml:"licenses>license,omitempty"`
	Copyright          string               `json:"copyright,omitempty" xml:"copyright,omitempty"`
	CPE                string               `json:"cpe,omitempty" xml:"cpe,omitempty"`
	PackageURL         string               `json:"purl,omitempty" xml:"purl,omitempty"`
	ExternalReferences *[]ExternalReference `json:"externalReferences,omitempty" xml:"externalReferences>reference,omitempty"`
	Modified           *bool                `json:"modified,omitempty" xml:"modified,omitempty"`
	Properties         *[]Property          `json:"properties,omitempty" xml:"properties>property,omitempty"`
	Components         *[]Component         `json:"components,omitempty" xml:"components>component,omitempty"`
	Vulnerabilities    *[]Result            `json:"vulnerabilities,omitempty" xml:"vulnerabilities>vulnerability,omitempty"`
}

// License - Component Licenses
type Licensecdx struct {
	ID   string `json:"id,omitempty" xml:"id,omitempty"`
	Name string `json:"name,omitempty" xml:"name,omitempty"`
	URL  string `json:"url,omitempty" xml:"url,omitempty"`
}

//Property - Component Properties
type Property struct {
	Name  string `json:"name" xml:"name,attr"`
	Value string `json:"value" xml:",chardata"`
}

//ExternalReference - Component External References
type ExternalReference struct {
	URL     string                `json:"url" xml:"url"`
	Comment string                `json:"comment,omitempty" xml:"comment,omitempty"`
	Type    ExternalReferenceType `json:"type" xml:"type,attr"`
}

//ExternalReferenceType - External Reference Type
type ExternalReferenceType string

// VEX Model
type VexBOM struct {
	BomRef             string             `json:"bom-ref" xml:"bom-ref"`
	ID                 string             `json:"id" xml:"id"`
	SourceVEX          SourceVEX          `json:"source" xml:"source"`
	RatingsVEX         RatingVEX          `json:"ratings" xml:"ratings"`
	CWEs               *[]int             `json:"cwes,omitempty" xml:"cwes>cwe,omitempty"`
	Description        *string            `json:"description,omitempty" xml:"description,omitempty"`
	Detail             *string            `json:"detail,omitempty" xml:"detail,omitempty"`
	Recommendation     *string            `json:"recommendation,omitempty" xml:"recommendation,omitempty"`
	Advisories         *[]AdvisoryVEX     `json:"advisories,omitempty" xml:"advisories>advisory,omitempty"`
	VulnerabilitiesVEX []VulnerabilityVEX `json:"vulnerability-exposure,omitempty" xml:"vulnerability-exposure>vulnerability,omitempty"`
	AnalysisVEX        *AnalysisVEX       `json:"analysis,omitempty" xml:"analysis,omitempty"`
	AffectsVEX         []AffectVEX        `json:"affects" xml:"affects"`
	CreatedVEX         string             `json:"created,omitempty" xml:"created,omitempty"`
	PublishedVEX       string             `json:"published,omitempty" xml:"published,omitempty"`
	UpdatedVEX         string             `json:"updated,omitempty" xml:"updated,omitempty"`
	CreditsVEX         *CreditsVEX        `json:"credits,omitempty" xml:"credits,omitempty"`
	ToolsVEX           *[]Tool            `json:"tools,omitempty" xml:"tools>tool,omitempty"`
}

type VulnerabilityVEX struct {
	VulnerabilityID string      `json:"id" xml:"id"`
	Source          SourceVEX   `json:"source" xml:"source"`
	Description     string      `json:"description,omitempty" xml:"description,omitempty"`
	BaseScore       float64     `json:"base_score,omitempty" xml:"base_score,omitempty"`
	Severity        string      `json:"severity" xml:"severity"`
	References      []string    `json:"reference" xml:"reference"`
	RatingsVEX      []RatingVEX `json:"ratings" xml:"ratings"`
}

type SourceVEX struct {
	Name string `json:"name" xml:"name"`
	Url  string `json:"url" xml:"url"`
}

type RatingVEX struct {
	SourceVEX   SourceVEX `json:"source" xml:"source"`
	Description *string   `json:"description,omitempty" xml:"description,omitempty"` // Package Description
	BaseScore   float64   `json:"base_score,omitempty" xml:"base_score,omitempty"`
	Severity    string    `json:"severity" xml:"severity"`
	Method      string    `json:"method" xml:"method"`                     // e.g. CVSSv31,
	Vector      string    `json:"vector,omitempty" xml:"vector,omitempty"` // AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A
}

type AnalysisVEX struct {
	State         string   `json:"state,omitempty" xml:"state,omitempty"` // affected, not_affected
	Justification string   `json:"justification,omitempty" xml:"justification,omitempty"`
	Response      []string `json:"response,omitempty" xml:"response,omitempty"` // ["will_not_fix", "update"]
	Detail        string   `json:"detail,omitempty" xml:"detail,omitempty"`     // Vulnerability Detail
}

type AffectVEX struct {
	Ref string `json:"ref" xml:"ref"`
}

type CreditsVEX struct {
	Organizations *[]OrganizationalEntityVEX `json:"organizations,omitempty" xml:"organizations>organization,omitempty"`
	Individuals   *[]IndividualContactVEX    `json:"individuals,omitempty" xml:"individuals>individual,omitempty"`
}
type IndividualContactVEX struct {
	Name  string `json:"name,omitempty" xml:"name,omitempty"`
	Email string `json:"email,omitempty" xml:"email,omitempty"`
	Phone string `json:"phone,omitempty" xml:"phone,omitempty"`
}

type OrganizationalEntityVEX struct {
	Name    string                  `json:"name" xml:"name"`
	URL     *[]string               `json:"url,omitempty" xml:"url,omitempty"`
	Contact *[]IndividualContactVEX `json:"contact,omitempty" xml:"contact,omitempty"`
}

type AdvisoryVEX struct {
	Title string `json:"title,omitempty" xml:"title,omitempty"`
	Url   string `json:"url" xml:"url"`
}
