package spinner

import (
	"time"

	"github.com/carbonetes/jacked/internal/logger"
	"github.com/theckman/yacspin"
)

var (
	cfg = yacspin.Config{
		TerminalMode:      yacspin.AutomaticMode,
		Frequency:         80 * time.Millisecond,
		Colors:            []string{"fgYellow"},
		StopCharacter:     "✓",
		StopColors:        []string{"fgGreen"},
		StopFailCharacter: "✗",
		StopFailColors:    []string{"fgRed"},
		CharSet:           yacspin.CharSets[14],
	}
	spin    *yacspin.Spinner
	disable = true
	log     = logger.GetLogger()
	err     error
)

func init() {
	spin, err = yacspin.New(cfg)
	if err != nil {
		log.Errorln(err.Error())
	}
}

func Start() {
	if disable {
		return
	}
	err = spin.Start()
	if err != nil {
		log.Errorln(err.Error())
	}

}

func SetMessage(str string) {
	if disable {
		return
	}
	spin.Suffix(" " + str)

}

func Stop() {
	if disable {
		return
	}
	err = spin.Stop()
	if err != nil {
		log.Errorln(err.Error())
	}

}

func StopFail() {
	if disable {
		return
	}
	err = spin.StopFail()
	if err != nil {
		log.Errorln(err.Error())
	}

}

func Enable() {
	disable = false
}
