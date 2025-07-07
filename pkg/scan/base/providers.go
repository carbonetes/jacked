package base

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/pkg/model"
)

// APKVulnerabilityProvider provides vulnerabilities for APK packages
type APKVulnerabilityProvider struct {
	store db.Store
}

func NewAPKVulnerabilityProvider(store db.Store) *APKVulnerabilityProvider {
	return &APKVulnerabilityProvider{store: store}
}

func (p *APKVulnerabilityProvider) GetVulnerabilities(component cyclonedx.Component) *[]model.Vulnerability {
	vulns := p.store.ApkSecDBMatch(component.Name)

	// Also check upstream packages
	upstream := helper.FindUpstream(component.BOMRef)
	if upstream != "" {
		upstreamVulns := p.store.ApkSecDBMatch(upstream)
		if upstreamVulns != nil {
			if vulns == nil {
				vulns = upstreamVulns
			} else {
				*vulns = append(*vulns, *upstreamVulns...)
			}
		}
	}

	return vulns
}

// DpkgVulnerabilityProvider provides vulnerabilities for DPKG packages
type DpkgVulnerabilityProvider struct {
	store db.Store
}

func NewDpkgVulnerabilityProvider(store db.Store) *DpkgVulnerabilityProvider {
	return &DpkgVulnerabilityProvider{store: store}
}

func (p *DpkgVulnerabilityProvider) GetVulnerabilities(component cyclonedx.Component) *[]model.Vulnerability {
	vulns := p.store.DebSecTrackerMatch(component.Name)

	// Also check upstream packages
	upstream := helper.FindUpstream(component.BOMRef)
	if upstream != "" {
		upstreamVulns := p.store.DebSecTrackerMatch(upstream)
		if upstreamVulns != nil {
			if vulns == nil {
				vulns = upstreamVulns
			} else {
				*vulns = append(*vulns, *upstreamVulns...)
			}
		}
	}

	return vulns
}

// RPMVulnerabilityProvider provides vulnerabilities for RPM packages
type RPMVulnerabilityProvider struct {
	store db.Store
}

func NewRPMVulnerabilityProvider(store db.Store) *RPMVulnerabilityProvider {
	return &RPMVulnerabilityProvider{store: store}
}

func (p *RPMVulnerabilityProvider) GetVulnerabilities(component cyclonedx.Component) *[]model.Vulnerability {
	upstream := helper.FindUpstream(component.BOMRef)
	keywords := []string{component.Name}
	if upstream != "" {
		keywords = append(keywords, upstream)
	}
	return p.store.NVDMatchWithPackageNames(keywords)
}

// KeywordVulnerabilityProvider provides vulnerabilities using keyword-based matching (NVD)
type KeywordVulnerabilityProvider struct {
	store db.Store
}

func NewKeywordVulnerabilityProvider(store db.Store) *KeywordVulnerabilityProvider {
	return &KeywordVulnerabilityProvider{store: store}
}

func (p *KeywordVulnerabilityProvider) GetVulnerabilities(component cyclonedx.Component) *[]model.Vulnerability {
	upstream := helper.FindUpstream(component.BOMRef)
	keywords := []string{component.Name}
	if upstream != "" {
		keywords = append(keywords, upstream)
	}
	return p.store.NVDMatchWithKeywords(keywords)
}
