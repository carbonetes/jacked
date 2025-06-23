package build

import "runtime"

// Build contains information about the build of the application.
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

// Placeholder is used for default values when build information is not available.
const placeholder string = "not available"

// Variable has been set as "not available" as Default Value. Values provided as Built-Time Arguments.
var (
	application string = "jacked"
	version     string = placeholder
	buildDate   string = placeholder
	gitCommit   string = placeholder
	gitDesc     string = placeholder
	goVersion   string = runtime.Version()
	compiler    string = runtime.Compiler
	platform    string = runtime.GOOS + "/" + runtime.GOARCH
)

// GetBuild returns the build information of the application.
func GetBuild() Build {
	return Build{
		Application: application, // Application Name
		Version:     version,     // Jacked Version
		BuildDate:   buildDate,   // Date of the build
		GitCommit:   gitCommit,   // git SHA at build-time
		GitDesc:     gitDesc,     // output of 'git describe --dirty --always --tags'
		GoVersion:   goVersion,   // go runtime version at build-time
		Compiler:    compiler,    // compiler used at build-time
		Platform:    platform,    // GOOS and GOARCH at build-time
	}

}
