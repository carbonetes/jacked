package assessment

import (
	"testing"
	"github.com/carbonetes/diggity/pkg/convert"
	"github.com/carbonetes/jacked/pkg/core/model"
	dm "github.com/carbonetes/diggity/pkg/model"
	diggity "github.com/carbonetes/diggity/pkg/scanner"
)


type Validator struct{
	image		string
	expected	*Assessment
}

func TestEvaluate(t *testing.T) {
	tests := []Validator{
		{"alpine", nil},
		{"ubuntu", nil},
	}
    var m = model.NewArguments()
    var d = dm.NewArguments()
	

	for _, test := range tests{
		d.Image = &test.image
    
		sbom, _ := diggity.Scan(d)
		cdx := convert.ToCDX(sbom.Packages)
		if result := Evaluate(m.FailCriteria, cdx); result != test.expected{
			t.Error("Test Failed: Error on the Evaluate function")
		}
	}
}
