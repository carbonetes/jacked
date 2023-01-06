package model

type JavaMetadata struct {
	Manifest         Manifest         `json:"Manifest"`
	ManifestLocation ManifestLocation `json:"ManifestLocation"`
	PomProperties    PomProperties    `json:"PomProperties"`
	PomProject       PomProject       `json:"PomProject"`
}

type PomProject struct {
	GroupID string `json:"groupID"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type PomProperties struct {
	ArtifactId string `json:"artifactId"`
	GroupId    string `json:"groupId"`
	Location   string `json:"location"`
	Name       string `json:"name"`
	Version    string `json:"version"`
}

type Manifest struct {
	AutomaticModuleName   string `json:"Automatic-Module-Name"`
	ArchiverVersion       string `json:"Archiver-Version"`
	BndLastModified       string `json:"Bnd-LastModified"`
	BuildJdk              string `json:"Build-Jdk"`
	BundleDescription     string `json:"Bundle-Description"`
	BundleDocURL          string `json:"Bundle-DocURL"`
	BundleLicense         string `json:"Bundle-License"`
	BundleManifestVersion string `json:"Bundle-ManifestVersion"`
	BundleName            string `json:"Bundle-Name"`
	BundleSymbolicName    string `json:"Bundle-SymbolicName"`
	BundleVendor          string `json:"Bundle-Vendor"`
	BundleVersion         string `json:"Bundle-Version"`
	CreatedBy             string `json:"Created-By"`
	ImplementationTitle   string `json:"Implementation-Title"`
	ImplemenrationVersion string `json:"Implementation-Version"`
	EmbedDependency       string `json:"Embed-Dependency"`
	ExportPackage         string `json:"Export-Package"`
	ManifestVersion       string `json:"ManifestVersion"`
	Tool                  string `json:"Tool"`
}

type ManifestLocation struct {
	Path string `json:"path"`
}

