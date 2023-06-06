package ci

import (
	"testing"
	"github.com/carbonetes/jacked/pkg/core/model"
	"github.com/carbonetes/jacked/internal/config"
)

type Validator struct{
	image		string
	expected	int
}

func TestAnalyze(t *testing.T) {
	tests := []Validator{
		{"alpine", 1},
		{"", -1},
		{"busybox", 1},
	}

    var m = model.NewArguments()
	var config config.CIConfiguration
    
	for _,test := range tests {
		m.Image = &test.image
		if result :=  Analyze(m,&config, true); result != test.expected {
			t.Error("Test Failed: Analyze function is not working properly")
		}
	}

}

