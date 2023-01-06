package events

import (
	diggity "github.com/carbonetes/diggity/pkg/event-bus"
)

const (
	secretMaxFileSize int    = 10485760
	secretRegex       string = "API_KEY|SECRET_KEY|DOCKER_AUTH"
	event             string = "event"
	quiet             bool   = true
)

// Get arguments instance from diggity
var arguments = diggity.GetArguments()

// Construct a valid arguments to request for sbom
func loadArgs(image *string) {
	arguments.Image = image
	arguments.SecretMaxFileSize = int64(secretMaxFileSize)
	*arguments.SecretContentRegex = secretRegex
	*arguments.Quiet = quiet
}
