package logger

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
	easy "github.com/t-tomalak/logrus-easy-formatter"
)

var log *logrus.Logger

// Create a new logger and set it to simple mode
func init() {
	log = logrus.New()
	SetSimpleMode()
}

func SetQuietMode() {
	log.SetOutput(io.Discard)
}

// Enable simple logging by displaying only the log messages
func SetSimpleMode() {
	log = &logrus.Logger{
		Out: os.Stderr,
		ExitFunc: func(i int) {
			os.Exit(i)
		},
		Level: logrus.DebugLevel,
		Formatter: &easy.Formatter{
			LogFormat: "%msg%\n",
		},
	}
}

// Returns the created logger instance
func GetLogger() *logrus.Logger {
	return log
}
