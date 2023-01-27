package test

import (
	"reflect"
	"testing"

	"github.com/carbonetes/jacked/internal/events"
)

var (
	image = "nginx"
)

func TestEventBus(t *testing.T) {
	var fetch = events.RequestSBOMAnalysis(&image)
	if reflect.ValueOf(fetch).IsNil() { // trigger func, return fail if nil, panic error
		t.Fail()
	}
}
