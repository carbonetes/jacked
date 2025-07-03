package build

import "runtime"

// Build contains information about the build of the application.
type Build struct {
	Application string `json:"application"`
	Version     string `json:"version"`
	BuildDate   string `json:"buildDate"`
	GitCommit   string `json:"gitCommit"`
	GitDesc     string `json:"gitDesc"`
	GoVersion   string `json:"goVersion"`
	Compiler    string `json:"compiler"`
	Platform    string `json:"platform"`
}

// Default values when build information is not available.
const notAvailable = "not available"

// Build-time variables (set during build)
var (
	application = "jacked"
	version     = notAvailable
	buildDate   = notAvailable
	gitCommit   = notAvailable
	gitDesc     = notAvailable
)

// GetBuild returns the build information of the application.
func GetBuild() Build {
	return Build{
		Application: application,
		Version:     version,
		BuildDate:   buildDate,
		GitCommit:   gitCommit,
		GitDesc:     gitDesc,
		GoVersion:   runtime.Version(),
		Compiler:    runtime.Compiler,
		Platform:    runtime.GOOS + "/" + runtime.GOARCH,
	}
}
