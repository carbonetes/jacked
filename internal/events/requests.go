package events

import (
	diggity "github.com/carbonetes/diggity/pkg/event-bus"

	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/model"
	"github.com/carbonetes/jacked/internal/ui/spinner"

	"github.com/google/uuid"
	"github.com/vmware/transport-go/bus"
	tm "github.com/vmware/transport-go/model"
)

var (
	tr  = bus.GetBus()
	log = logger.GetLogger()
)

// Send a request for sbom to diggity through a event bus
func RequestSBOMAnalysis(newArgs *model.Arguments) []byte {
	spinner.OnSBOMRequestStart(*newArgs.Image)

	// Prepare arguments
	loadArgs(newArgs)

	// Construct unique channel
	channel := *newArgs.Image + "-request-" + uuid.New().String()

	// Create the channel in event bus
	tr.GetChannelManager().CreateChannel(channel)

	// Set the handler for receiving request in diggity
	diggity.SetAnalysisRequestHandler(channel)

	// Initiate the transmission of request with the arguments to diggity
	responseHandler, err := tr.RequestStream(channel, arguments)

	if err != nil {
		log.Fatalf("Error initializing response handler: %v", err)
	}

	// Once the request has been sent to diggity -- this handler will wait for the sbom response
	sbomchan := make(chan []byte, 1)
	responseHandler.Handle(
		func(msg *tm.Message) {
			// Payload type is set by default to string
			sbom := []byte(msg.Payload.(string))
			// Destroy the channel after receiving the response
			tr.GetChannelManager().DestroyChannel(channel)
			sbomchan <- sbom
			spinner.OnSBOMRequestEnd(nil)
		},
		func(err error) {
			log.Fatalf("Error handling response: %v", err)
		})
	// Start the response handler for receiving the response
	err = responseHandler.Fire()
	if err != nil {
		log.Fatalf("Cannot start response handler: %v", err)
	}
	return <-sbomchan
}
