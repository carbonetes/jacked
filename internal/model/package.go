package model

type Package struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Vendor      string      `json:"-"`
	Type        string      `json:"type"`
	Version     string      `json:"version"`
	Path        string      `json:"path"`
	Locations   []Location  `json:"locations"`
	Description string      `json:"description"`
	Licenses    []string    `json:"licenses"`
	CPEs        []string    `json:"cpes"`
	PURL        PURL        `json:"purl"`
	Metadata    interface{} `json:"metadata"`
	Keywords    []string    `json:"-"`
}

type PURL string

type Location struct {
	Path      string `json:"path"`
	LayerHash string `json:"layerHash"`
}

type PackageMetadata struct {
	Architecture         string                `json:"Architecture,omitempty"`
	BuildTimestamp       string                `json:"BuildTimestamp,omitempty"`
	Files                []PackageMetadataFile `json:"Files,omitempty"`
	GitCommitHashApk     string                `json:"GitCommitHashApk,omitempty"`
	License              string                `json:"License,omitempty"`
	Maintainer           string                `json:"Maintainer,omitempty"`
	PackageDescription   string                `json:"PackageDescription,omitempty"`
	PackageInstalledSize string                `json:"PackageInstalledSize,omitempty"`
	PackageName          string                `json:"PackageName,omitempty"`
	PackageOrigin        string                `json:"PackageOrigin,omitempty"`
	PackageSize          string                `json:"PackageSize,omitempty"`
	PackageURL           string                `json:"PackageURL,omitempty"`
	PackageVersion       string                `json:"PackageVersion,omitempty"`
	Provides             string                `json:"Provides,omitempty"`
	PullChecksum         string                `json:"PullChecksum,omitempty"`
	PullDependencies     string                `json:"PullDependencies,omitempty"`
}

type PackageMetadataFile struct {
	Path        string                    `json:"path,omitempty"`
	Digest      PackageMetadataFileDigest `json:"digest,omitempty"`
	OwnerGid    string                    `json:"ownerGid,omitempty"`
	OwnerUID    string                    `json:"ownerUid,omitempty"`
	Permissions string                    `json:"permissions,omitempty"`
}

type PackageMetadataFileDigest struct {
	Algorithm string `json:"algorithm,omitempty"`
	Value     string `json:"value,omitempty"`
}
