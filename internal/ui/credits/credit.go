package credits

import (
	"fmt"
	log "github.com/carbonetes/jacked/internal/logger"

	"github.com/savioxavier/termlink"
)

const (
	githubLink = "https://github.com/carbonetes/jacked"

	footerMessage = "🚀 For more information, please visit "
	credits       = "Made by: Carbonetes"
)

func Show(){
	log := log.GetLogger()
	link := termlink.ColorLink("Jacked", githubLink, "green")
	fullMessage := fmt.Sprintf(footerMessage + link)
	log.Println()
	log.Println(fullMessage)
	log.Println(credits)
}
