package version

// Build information from the Application
type Build struct {
	Application string `json:"Application"`
	Version     string `json:"Version"`
	BuildDate   string `json:"BuildDate"`
	GitCommit   string `json:"GitCommit"`
	GitDesc     string `json:"GitDesc"`
	GoVersion   string `json:"GoVersion"`
	Compiler    string `json:"Compiler"`
	Platform    string `json:"Platform"`
}
