package spinner

import (
	"time"

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
)

func init() {
	spin, _ = yacspin.New(cfg)
}

func Start() {
	if _switch {
		spin.Start()
	}
}

func SetMessage(str string) {
	if _switch {
		spin.Suffix(" " + str)
	}
}

func Stop() {
	if _switch {
		spin.Stop()
	}
}

func StopFail() {
	if _switch {
		spin.StopFail()
	}
}

func Disable() {
	_switch = false
}
