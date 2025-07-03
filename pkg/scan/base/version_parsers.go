package base

import (
	"github.com/carbonetes/jacked/pkg/version"
)

// NPMVersionParser handles npm version parsing
type NPMVersionParser struct{}

func NewNPMVersionParser() *NPMVersionParser {
	return &NPMVersionParser{}
}

func (p *NPMVersionParser) Parse(versionStr string) (VersionChecker, error) {
	return version.NewNpmVersion(versionStr)
}

// GoVersionParser handles Go version parsing
type GoVersionParser struct{}

func NewGoVersionParser() *GoVersionParser {
	return &GoVersionParser{}
}

func (p *GoVersionParser) Parse(versionStr string) (VersionChecker, error) {
	return version.NewGoVersion(versionStr)
}

// MavenVersionParser handles Maven version parsing
type MavenVersionParser struct{}

func NewMavenVersionParser() *MavenVersionParser {
	return &MavenVersionParser{}
}

func (p *MavenVersionParser) Parse(versionStr string) (VersionChecker, error) {
	return version.NewMavenVersion(versionStr)
}

// PythonVersionParser handles Python version parsing
type PythonVersionParser struct{}

func NewPythonVersionParser() *PythonVersionParser {
	return &PythonVersionParser{}
}

func (p *PythonVersionParser) Parse(versionStr string) (VersionChecker, error) {
	// Try PEP440 first, fall back to semantic versioning
	pep440Ver, err := version.NewPEP440Version(versionStr)
	if err == nil {
		return pep440Ver, nil
	}

	return NewSemanticVersionWrapper(versionStr)
}

// RubyVersionParser handles Ruby Gem version parsing
type RubyVersionParser struct{}

func NewRubyVersionParser() *RubyVersionParser {
	return &RubyVersionParser{}
}

func (p *RubyVersionParser) Parse(versionStr string) (VersionChecker, error) {
	return version.NewGemVersion(versionStr)
}

// APKVersionParser handles APK version parsing
type APKVersionParser struct{}

func NewAPKVersionParser() *APKVersionParser {
	return &APKVersionParser{}
}

func (p *APKVersionParser) Parse(versionStr string) (VersionChecker, error) {
	return version.NewApkVersion(versionStr)
}

// DpkgVersionParser handles DPKG version parsing
type DpkgVersionParser struct{}

func NewDpkgVersionParser() *DpkgVersionParser {
	return &DpkgVersionParser{}
}

func (p *DpkgVersionParser) Parse(versionStr string) (VersionChecker, error) {
	return version.NewDpkgVersion(versionStr)
}

// RPMVersionParser handles RPM version parsing
type RPMVersionParser struct{}

func NewRPMVersionParser() *RPMVersionParser {
	return &RPMVersionParser{}
}

func (p *RPMVersionParser) Parse(versionStr string) (VersionChecker, error) {
	return version.NewRPMVersion(versionStr)
}

// SemanticVersionParser handles generic semantic version parsing
type SemanticVersionParser struct{}

func NewSemanticVersionParser() *SemanticVersionParser {
	return &SemanticVersionParser{}
}

func (p *SemanticVersionParser) Parse(versionStr string) (VersionChecker, error) {
	return NewSemanticVersionWrapper(versionStr)
}
