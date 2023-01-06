package version

import "runtime"

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
