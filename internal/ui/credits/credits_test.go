package credits

import (
	"testing"
)

func TestShow(t *testing.T) {
	if Show(true) < 1 {
		t.Error("Failed: Show Credits is not working")
	}
}
