package output

import (
	"testing"

	dm "github.com/carbonetes/diggity/pkg/model"
	diggity "github.com/carbonetes/jacked/internal/sbom"
	"github.com/carbonetes/jacked/pkg/core/model"
)

type Validator struct{
	image		string
	expected	int
}

var (
	sbom            *dm.SBOM
	args =          model.NewArguments()
    tests =         []Validator{
					{"alpine", 1},
					{"busybox", 1},
	}
)

func TestPrintJsonResult(t *testing.T) {
	
	for _, test := range tests{
		args.Image = &test.image
		sbom = diggity.Scan(args)
		
		if result := len(printJsonResult(sbom)); result < test.expected{
			t.Error("Test Failed: Json output is not working properly")
		}
	}
}