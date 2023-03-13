package update

import (
	"context"
	"strings"

	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/version"
	"github.com/google/go-github/github"
	"github.com/savioxavier/termlink"
)

const (
	appName = "jacked"
	owner   = "carbonetes"
	repo    = "jacked"

	newVersionMsg     = "🔄 New Version Detected: "
	currentVersionMsg = "Current Version: "

	githubReleaseLink = "https://github.com/carbonetes/jacked/releases/tag/"
)

var (
	log              = logger.GetLogger()
	installedVersion string
	latestVersion    string
)

func ShowLatestVersion() error {

	getLatestVersion()
	// Compare version, if version is not latest, show latest version
	if !(strings.EqualFold("v"+installedVersion, latestVersion)) {

		link := termlink.ColorLink(latestVersion, githubReleaseLink+latestVersion, "green")
		log.Println(newVersionMsg + link)
	}
	return nil
}

func getLatestVersion() {

	// Check the installed version of the binary
	info := version.GetBuild()
	installedVersion = info.Version
	context := context.Background()

	// Get the latest release from GitHub
	client := github.NewClient(nil)
	release, _, err := client.Repositories.GetLatestRelease(context, owner, repo)
	if err != nil {
		log.Errorf("Error getting latest release: %v", err)

	}
	latestVersion = *release.TagName
}
