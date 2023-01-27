package events

import (
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
