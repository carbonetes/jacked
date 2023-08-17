package filter

import (
	"testing"
	"github.com/carbonetes/diggity/pkg/convert"
	dm "github.com/carbonetes/diggity/pkg/model"
	diggity "github.com/carbonetes/diggity/pkg/scanner"
	jacked "github.com/carbonetes/jacked/pkg/core/analysis"
	"github.com/carbonetes/jacked/internal/config"

)


type Validator struct{
	image		string
	expected	int
}

func TestIgnoreVuln(t *testing.T) {
	var cfg config.CIConfiguration
	var d = dm.NewArguments()

	tests := []Validator{
		{"alpine", 1},
		{"busybox", 0},
	}
  
	for _, test := range tests{
		d.Image = &test.image
    
		sbom, _ := diggity.Scan(d)
		cdx := convert.ToCDX(sbom)
		jacked.AnalyzeCDX(cdx)
		
		IgnoreVuln(cdx.Vulnerabilities, &cfg.FailCriteria.Vulnerability)
		if  len(*cdx.Vulnerabilities) != test.expected{
			t.Error("Test Failed: Error on the Ignore Vuln function")
		}
	}
}
