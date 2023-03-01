package events

import (
	"strings"

	diggity "github.com/carbonetes/diggity/pkg/event-bus"
	"github.com/carbonetes/jacked/internal/model"
)

const (
	event string = "event"
	quiet bool   = true
)

// Get arguments instance from diggity
var arguments = diggity.GetArguments()

// Construct a valid arguments to request for sbom
func loadArgs(newArgs *model.Arguments) {

	setArgsFormat(newArgs)
	arguments.Dir = newArgs.Dir
	arguments.DisableFileListing = newArgs.DisableFileListing
	arguments.DisableSecretSearch = newArgs.DisableSecretSearch
	arguments.EnabledParsers = newArgs.EnabledParsers
	arguments.ExcludedFilenames = newArgs.ExcludedFilenames
	arguments.Image = newArgs.Image
	*arguments.Quiet = quiet
	arguments.RegistryURI = newArgs.RegistryURI
	arguments.RegistryPassword = newArgs.RegistryPassword
	arguments.RegistryToken = newArgs.RegistryToken
	arguments.RegistryUsername = newArgs.RegistryUsername
	arguments.Tar = newArgs.Tar
	arguments.SecretMaxFileSize = int64(newArgs.SecretMaxFileSize)
	arguments.SecretContentRegex = newArgs.SecretContentRegex
}

// Set Args Split
func setArgsFormat(newArgs *model.Arguments) {

	// Split Args for EnabledParsers & ExcludedFileNames
	enabledParsers := splitArgs(*newArgs.EnabledParsers)
	newArgs.EnabledParsers = &enabledParsers

	// Split Args for EnabledParsers & ExcludedFileNames
	excludedFilenames := splitArgs(*newArgs.ExcludedFilenames)
	newArgs.ExcludedFilenames = &excludedFilenames
}

// SplitArgs splits arguments with comma, if any
func splitArgs(args []string) (result []string) {
	for _, arg := range args {
		if !strings.Contains(arg, ",") {
			result = append(result, arg)
			continue
		}
		result = append(result, strings.Split(arg, ",")...)
	}
	return result
}
