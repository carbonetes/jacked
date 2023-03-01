package credits

import (
	log "github.com/carbonetes/jacked/internal/logger"

	"github.com/savioxavier/termlink"
)

const (
	githubLink = "https://github.com/carbonetes/jacked"

	footerMessage = "🚀 For more information, please visit "
	credits       = "Made by: Carbonetes"
)

func Show() {
	log := log.GetLogger()
	link := termlink.ColorLink("Jacked", githubLink, "green")
	log.Println(footerMessage + link)
	log.Println(credits)
}
