package cyclonedx

import(
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

func TestPrintCycloneDXJSON(t *testing.T) {

   for _, test := range tests{
		args.Image = &test.image
		sbom = diggity.Scan(args)
		
		if result := len(PrintCycloneDXJSON(sbom)); result < test.expected{
			t.Error("Test Failed: CyclonedDXJSON output is not working properly")
		}
	}
}

func TestPrintCycloneDXXML(t *testing.T) {

   for _, test := range tests{
		args.Image = &test.image
		sbom = diggity.Scan(args)
		
		if result := len(PrintCycloneDXXML(sbom)); result < test.expected{
			t.Error("Test Failed: CyclonedDXXML output is not working properly")
		}
	}
}
