package model

type AlpineMetadata struct {
	Architecture         string       `json:"Architecture"`
	BuildTimestamp       string       `json:"BuildTimestamp"`
	Files                []AlpineFile `json:"Files"`
	GitCommitHashApk     string       `json:"GitCommitHashApk"`
	License              string       `json:"License"`
	Maintainer           string       `json:"Maintainer"`
	PackageDescription   string       `json:"PackageDescription"`
	PackageInstalledSize string       `json:"PackageInstalledSize"`
	PackageName          string       `json:"PackageName"`
	PackageOrigin        string       `json:"PackageOrigin"`
	PackageSize          string       `json:"PackageSize"`
	PackageURL           string       `json:"PackageURL"`
	PackageVersion       string       `json:"PackageVersion"`
	Provides             string       `json:"Provides"`
	PullChecksum         string       `json:"PullChecksum"`
	PullDependencies     string       `json:"PullDependencies"`
}

type AlpineFile struct {
	Path        string       `json:"path"`
	Digest      AlpineDigest `json:"digest"`
	OwnerGid    string       `json:"ownerGid"`
	OwnerUid    string       `json:"ownerUid"`
	Permissions string       `json:"permissions"`
}

type AlpineDigest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type AlpineManifest map[string]interface{}
