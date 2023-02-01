package spinner

import (
	"time"

	"github.com/carbonetes/jacked/internal/logger"
	"github.com/theckman/yacspin"
)

var (
	cfg = yacspin.Config{
		Frequency:         80 * time.Millisecond,
		Colors:            []string{"fgYellow"},
		StopCharacter:     "✓",
		StopColors:        []string{"fgGreen"},
		StopFailCharacter: "✗",
		StopFailColors:    []string{"fgRed"},
		CharSet:           yacspin.CharSets[14],
	}
	spin    *yacspin.Spinner
	_switch bool = true
	log          = logger.GetLogger()
	err     error
)

func init() {
	spin, err = yacspin.New(cfg)
	if err != nil {
		log.Errorln(err.Error())
	}
}

func Start() {
	if _switch {
		err = spin.Start()
		if err != nil {
			log.Errorln(err.Error())
		}
	}
}

func SetMessage(str string) {
	if _switch {
		spin.Suffix(" " + str)
	}
}

func Stop() {
	if _switch {
		err = spin.Stop()
		if err != nil {
			log.Errorln(err.Error())
		}
	}
}

func StopFail() {
	if _switch {
		err = spin.StopFail()
		if err != nil {
			log.Errorln(err.Error())
		}
	}
}

func Disable() {
	_switch = false
}
