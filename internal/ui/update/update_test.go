package update

import (
	"testing"
)

func TestShowLatestVersion(t *testing.T){
	err := ShowLatestVersion()

	if err != nil {
		t.Errorf("Failed: Error on show latest version: %v", err)
	}
}